//! The local audit ledger, Yonder 0.2.0 design section 12: a persistent,
//! hash-chained record of every finalized local audit record, serialized by
//! a cross-process exclusive lock that is held only during the three short
//! phases of the design — first initialization, pending-record recovery and
//! the final session commit (section 12.2).
//!
//! # Layout (sections 10.4 and 12.1)
//!
//! ```text
//! Audit/
//! ├── identity.ed25519   persistent Ed25519 audit identity (identity module)
//! ├── ledger.state       current sequence and root, fixed-size binary
//! ├── ledger.lock        cross-process exclusive lock file
//! └── records/           <session-id>.<role>.yonaudit containers
//! ```
//!
//! `ledger.state` is a fixed 82-byte record: an eight-byte magic, the format
//! version, the big-endian sequence, the 32-byte ledger root and a SHA-256
//! checksum over everything before it. It is never modified in place: every
//! advance writes a private temporary file, syncs it, atomically renames it
//! over `ledger.state`, and syncs the parent directory on Unix (section
//! 12.3, steps 8-10).
//!
//! # Chain and root formula (sections 12.1 and 17.3)
//!
//! ```text
//! root_{n+1} = SHA-256(LEDGER_COMMIT_DOMAIN
//!                      || sequence_{n+1} || root_n || session_id
//!                      || manifest_digest || sealed_record_digest
//!                      || peer_identity_fingerprint || session_result)
//! ```
//!
//! That is exactly the SHA-256 of the persistent-identity-signed commit
//! bytes ([`LedgerCommit::signing_input`]), so the new root is the digest of
//! the signed commit and every later commit chains to it. The genesis root
//! is the fixed domain-separated constant
//! `SHA-256("yonder-audit-ledger-genesis-v2")`. Each commit carries the
//! eight fields of design section 12.1: local sequence, previous root,
//! session ID, final joint manifest digest, local sealed-record digest,
//! peer audit identity fingerprint, session result, and the persistent audit
//! identity signature.
//!
//! # Locking (section 12.2)
//!
//! `ledger.lock` is created exclusively (`0600`, never following a symlink)
//! and locked exclusively only inside [`Ledger::open`] (first initialization
//! plus recovery) and [`Ledger::begin_commit`] (the final session commit).
//! No lock is ever held across a session. The ledger snapshot carried by
//! `AuditHello` is only a session-start snapshot; the final commit is always
//! computed against the fresh head re-read under the lock
//! ([`CommitSession::commit`] / [`CommitSession::advance`]).
//!
//! # Non-circular finalization (section 12.3)
//!
//! The session layer appends the footer to the audit file between
//! [`CommitSession::commit`] and [`CommitSession::advance`] while the lock
//! is still held. The commit references the sealed-record digest, which
//! covers the container up to the end of the `LocalRecordSeal` — never the
//! commit itself or the final container digest — so the footer and the
//! ledger state never reference each other cyclically.
//!
//! # Crash recovery (section 12.4)
//!
//! Every lock acquisition scans `records/` for completed containers whose
//! embedded `LedgerCommit` could connect directly to the current head. A
//! candidate must be a complete container (footer magic and a legal final
//! container digest), must contain a commit signed by the local persistent
//! audit identity whose `sealed_record_digest` matches the sealed prefix of
//! the file, and must have `sequence == head + 1` with
//! `previous_root == head.root`. At most one candidate is advanced;
//! multiple candidates, a legally signed commit that claims a future
//! sequence, or a legally signed candidate that does not link to the head
//! are all [`AuditLedgerError::AuditLedgerConflict`] and reject new sessions
//! (fail closed). Interrupted, tampered or foreign-signed records simply
//! cannot enter the ledger.
//!
//! Recovery never reads a whole record into memory: it parses only a
//! bounded tail of the file for the footer and verifies both digests in a
//! single streaming pass (design sections 27.1 and 27.2).

use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use yonder_core::wire::audit::{
    Digest32, Ed25519Signature, IdentityFingerprint, LedgerCommit, LedgerRoot, SessionId,
    SessionResult,
};
use yonder_core::wire::audit_container::{
    CONTAINER_DIGEST_LEN, CONTAINER_HEADER_LEN, DecodedFooter, FOOTER_MAGIC, MAX_FOOTER_PREFIX_LEN,
    decode_footer,
};
use yonder_core::{SecretFileError, SecretFilePolicy as _, SecureRandom, SystemSecretFilePolicy};

use super::identity::{self, AuditIdentity};

/// The private temporary file used for atomic `ledger.state` replacement.
/// The name is a scratch space of this module only; it is never referenced
/// by anything else and is never part of the documented layout.
#[cfg(test)]
pub const LEDGER_STATE_TMP_NAME: &str = ".ledger.state.tmp";

/// The fixed eight-byte ledger state magic.
const LEDGER_STATE_MAGIC: [u8; 8] = *b"YONLEDG\0";
/// The frozen ledger state format version.
const LEDGER_STATE_VERSION: u16 = 1;
/// Fixed ledger state size: magic, version, sequence, root and checksum.
const LEDGER_STATE_LEN: usize = LEDGER_STATE_MAGIC.len() + 2 + 8 + 32 + 32;
/// The checksum covers everything before it (magic, version, sequence,
/// root).
const LEDGER_STATE_CHECKSUM_OFFSET: usize = LEDGER_STATE_LEN - 32;

/// How many attempts are made to exclusively create `ledger.lock` before
/// failing; the bound only exists so a pathological race cannot loop.
const LOCK_CREATE_ATTEMPTS: usize = 8;

/// The record file extension of `.yonaudit` containers (design section
/// 23.1).
const RECORD_EXTENSION: &str = "yonaudit";

/// The bounded tail parsed for crash recovery: the largest possible footer
/// (footer magic plus the five `u16`-prefixed components) plus the final
/// container digest. Recovery never reads more than this from the end of a
/// record.
const RECOVERY_TAIL_LEN: usize = MAX_FOOTER_PREFIX_LEN + CONTAINER_DIGEST_LEN;

/// The streaming digest chunk size of the recovery verification pass.
const RECOVERY_CHUNK: usize = 64 * 1024;

/// The fixed genesis ledger root: `SHA-256("yonder-audit-ledger-genesis-v2")`.
static GENESIS_ROOT: std::sync::LazyLock<LedgerRoot> = std::sync::LazyLock::new(|| {
    LedgerRoot::new(Sha256::digest(b"yonder-audit-ledger-genesis-v2").into())
});

/// Errors of the local audit ledger, one category per design section 30
/// failure class. Messages are fixed, redacted and never contain paths.
#[derive(Debug, Error)]
pub enum AuditLedgerError {
    /// `AuditLedgerInvalid`: `ledger.state` is missing, malformed or
    /// inconsistent.
    #[error("the local audit ledger state is invalid")]
    AuditLedgerInvalid,
    /// `AuditLedgerConflict`: pending records conflict, fork or claim an
    /// illegal previous root; new sessions are rejected (section 12.4).
    #[error("the local audit ledger has conflicting or forked pending commits")]
    AuditLedgerConflict,
    /// A ledger file has invalid permissions or is a symlink
    /// (design section 11.1).
    #[error("the local audit ledger file permissions are invalid")]
    AuditLedgerPermissions,
    /// The local persistent audit identity is unavailable.
    #[error("the local audit identity is unavailable")]
    Identity(#[from] identity::AuditIdentityError),
    /// Acquiring the cross-process lock failed.
    #[error("failed to acquire the local audit ledger lock")]
    LockFailed(#[source] io::Error),
    /// Releasing the cross-process lock failed.
    #[error("failed to release the local audit ledger lock")]
    UnlockFailed(#[source] io::Error),
    /// Reading `ledger.state` failed.
    #[error("failed to read the local audit ledger state")]
    StateReadFailed(#[source] io::Error),
    /// Reading a pending audit record failed.
    #[error("failed to read a pending audit record")]
    RecordReadFailed(#[source] io::Error),
    /// `AuditLedgerCommitFailed`: writing or advancing `ledger.state` failed.
    #[error("failed to commit to the local audit ledger")]
    AuditLedgerCommitFailed(#[source] io::Error),
}

/// The local ledger head: the sequence and root of the latest committed
/// session (design section 12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerHead {
    sequence: u64,
    root: LedgerRoot,
}

impl LedgerHead {
    /// The genesis head of an empty ledger: sequence zero and the fixed
    /// domain-separated genesis root.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            sequence: 0,
            root: *GENESIS_ROOT,
        }
    }

    /// The local ledger sequence (0 for a genesis ledger).
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The current ledger root.
    #[must_use]
    pub const fn root(&self) -> LedgerRoot {
        self.root
    }
}

/// The inputs of one final session commit (design section 12.1). The
/// `sealed_record_digest` must cover the local audit container up to the end
/// of the `LocalRecordSeal` component (header, record frames, joint manifest
/// and both session signatures) and never the commit itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitInput {
    session_id: SessionId,
    manifest_digest: Digest32,
    sealed_record_digest: Digest32,
    peer_identity_fingerprint: IdentityFingerprint,
    result: SessionResult,
}

impl CommitInput {
    /// Builds a commit input.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        manifest_digest: Digest32,
        sealed_record_digest: Digest32,
        peer_identity_fingerprint: IdentityFingerprint,
        result: SessionResult,
    ) -> Self {
        Self {
            session_id,
            manifest_digest,
            sealed_record_digest,
            peer_identity_fingerprint,
            result,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The digest of the final joint manifest (design section 21.1).
    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }

    /// The digest of the local sealed record, excluding the commit itself.
    #[must_use]
    pub const fn sealed_record_digest(&self) -> Digest32 {
        self.sealed_record_digest
    }

    /// The audit identity fingerprint of the peer (design section 12.1).
    #[must_use]
    pub const fn peer_identity_fingerprint(&self) -> IdentityFingerprint {
        self.peer_identity_fingerprint
    }

    /// How the session ended.
    #[must_use]
    pub const fn result(&self) -> SessionResult {
        self.result
    }
}

/// The local audit ledger of one endpoint.
///
/// The ledger owns the persistent [`AuditIdentity`], exposes the
/// session-start snapshot for `AuditHello` ([`Ledger::head`]) and serializes
/// the final commit of every session ([`Ledger::begin_commit`]). `Debug` is
/// redacted: it never prints the audit root path.
pub struct Ledger {
    root: PathBuf,
    identity: AuditIdentity,
    head: LedgerHead,
}

impl std::fmt::Debug for Ledger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ledger")
            .field("identity", &self.identity)
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

impl Ledger {
    /// Opens the local audit ledger of the endpoint rooted at `root`,
    /// creating the whole audit layout on first use (design section 9.2 and
    /// 12.2, first lock phase):
    ///
    /// 1. ensure the private audit directories,
    /// 2. exclusively create or open `ledger.lock` and take the exclusive
    ///    cross-process lock,
    /// 3. create or load the persistent audit identity
    ///    ([`identity::open_or_create_identity`]),
    /// 4. load or atomically create the genesis `ledger.state`,
    /// 5. recover any pending completed records (section 12.4),
    /// 6. release the lock.
    ///
    /// The lock is never held after `open` returns; concurrent sessions can
    /// open the same ledger freely.
    pub fn open(root: &Path, random: &mut impl SecureRandom) -> Result<Self, AuditLedgerError> {
        identity::ensure_audit_dirs(root)?;
        let lock = acquire_ledger_lock(root)?;
        let identity = identity::open_or_create_identity(root, random)?;
        let head = load_or_create_state(root)?;
        let head = recover_pending_records(root, &identity, head)?;
        drop(lock);
        Ok(Self {
            root: root.to_path_buf(),
            identity,
            head,
        })
    }

    /// The persistent audit identity of this endpoint.
    #[must_use]
    pub fn identity(&self) -> &AuditIdentity {
        &self.identity
    }

    /// The ledger snapshot at session start, carried by `AuditHello`
    /// (design section 12.2). This is only a snapshot: the final commit is
    /// computed against the fresh head read under the lock.
    #[must_use]
    pub fn head(&self) -> LedgerHead {
        self.head
    }

    /// Starts the final session commit (design sections 12.2 and 12.3, lock
    /// phase three): acquires the cross-process lock, recovers any pending
    /// records and re-reads the latest head. The returned [`CommitSession`]
    /// holds the lock; the session layer builds the signed commit, appends
    /// the footer and the final container digest to the audit file, syncs
    /// the file, and then calls [`CommitSession::advance`] to atomically
    /// move `ledger.state` forward. The lock is released when the session
    /// is dropped.
    pub fn begin_commit(&mut self) -> Result<CommitSession<'_>, AuditLedgerError> {
        let lock = acquire_ledger_lock(&self.root)?;
        let head = read_ledger_state(&self.root.join(identity::LEDGER_STATE_FILE_NAME))?;
        let head = recover_pending_records(&self.root, &self.identity, head)?;
        Ok(CommitSession {
            ledger: self,
            _lock: lock,
            head,
        })
    }

    /// The owned variant of [`Ledger::begin_commit`]: acquires the
    /// cross-process lock, recovers any pending records and re-reads the
    /// latest head, consuming the ledger so the resulting
    /// [`OwnedCommitSession`] can outlive the borrow of `self` (used by the
    /// integration adapter, design section 12.2).
    pub fn begin_owned_commit(self) -> Result<OwnedCommitSession, AuditLedgerError> {
        let lock = acquire_ledger_lock(&self.root)?;
        let head = read_ledger_state(&self.root.join(identity::LEDGER_STATE_FILE_NAME))?;
        let head = recover_pending_records(&self.root, &self.identity, head)?;
        Ok(OwnedCommitSession {
            ledger: self,
            _lock: lock,
            head,
        })
    }
}

/// A lock-guarded finalization section that owns the ledger
/// (design section 12.2). The integration adapter (`audit::observer`) needs
/// to hold the lock across the footer writes while the ledger itself moves
/// between the session trait calls, which a borrow-based
/// [`CommitSession`] cannot express; this owned variant provides the same
/// serialization with the ledger taken by value and returned by
/// [`OwnedCommitSession::into_ledger`].
pub struct OwnedCommitSession {
    ledger: Ledger,
    _lock: LedgerLockGuard,
    head: LedgerHead,
}

impl OwnedCommitSession {
    /// The latest head at the moment the lock was acquired, after pending
    /// record recovery.
    #[must_use]
    pub fn head(&self) -> LedgerHead {
        self.head
    }

    /// Builds and signs the persistent-identity ledger commit
    /// (design section 12.1): sequence `head + 1`, the head root as the
    /// previous root, and the identity signature over the exact commit
    /// signing bytes. The commit references the sealed record digest and
    /// never the final container digest, so the footer and the ledger never
    /// reference each other cyclically (section 12.3).
    pub fn commit(&self, input: &CommitInput) -> Result<LedgerCommit, AuditLedgerError> {
        let sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(AuditLedgerError::AuditLedgerInvalid)?;
        let commit = LedgerCommit::new(
            sequence,
            self.head.root,
            input.session_id,
            input.manifest_digest,
            input.sealed_record_digest,
            input.peer_identity_fingerprint,
            input.result,
            Ed25519Signature::new([0; 64]),
        );
        let signature = self.ledger.identity.sign(commit.signing_input().as_slice());
        Ok(commit.with_signature(signature))
    }

    /// Atomically advances `ledger.state` to the head produced by `commit`
    /// (design section 12.3, steps 9-10): the commit must chain exactly to
    /// the head re-read under the lock, the new root is
    /// [`ledger_root_of`], and the state file is replaced atomically and
    /// synchronized. Consumes the session so the lock is released and the
    /// ledger is returned to the caller.
    pub fn advance(self, commit: &LedgerCommit) -> Result<Ledger, AuditLedgerError> {
        let expected_sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(AuditLedgerError::AuditLedgerInvalid)?;
        if commit.sequence() != expected_sequence || commit.previous_root() != &self.head.root {
            return Err(AuditLedgerError::AuditLedgerConflict);
        }
        let new_head = LedgerHead {
            sequence: expected_sequence,
            root: ledger_root_of(commit),
        };
        let OwnedCommitSession {
            mut ledger, _lock, ..
        } = self;
        write_ledger_state_atomic(&ledger.root, &new_head)?;
        ledger.head = new_head;
        Ok(ledger)
    }

    /// The owned ledger, for callers that never advance (the lock is
    /// released when the session is dropped).
    #[must_use]
    pub fn into_ledger(self) -> Ledger {
        self.ledger
    }
}

/// A short-lived lock-guarded finalization section (design section 12.2).
///
/// The exclusive `ledger.lock` is held from construction until the session
/// is dropped, so the session layer can build the commit, append the footer
/// to the audit file and synchronize it before advancing the ledger state —
/// all under the same lock the design requires (section 12.3, steps 5-10).
pub struct CommitSession<'a> {
    ledger: &'a mut Ledger,
    _lock: LedgerLockGuard,
    head: LedgerHead,
}

impl CommitSession<'_> {
    /// The latest head at the moment the lock was acquired, after pending
    /// record recovery.
    #[must_use]
    pub fn head(&self) -> LedgerHead {
        self.head
    }

    /// Builds and signs the persistent-identity ledger commit
    /// (design section 12.1): sequence `head + 1`, the head root as the
    /// previous root, and the identity signature over the exact commit
    /// signing bytes. The commit references the sealed record digest and
    /// never the final container digest, so the footer and the ledger never
    /// reference each other cyclically (section 12.3).
    pub fn commit(&self, input: &CommitInput) -> Result<LedgerCommit, AuditLedgerError> {
        let sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(AuditLedgerError::AuditLedgerInvalid)?;
        let commit = LedgerCommit::new(
            sequence,
            self.head.root,
            input.session_id,
            input.manifest_digest,
            input.sealed_record_digest,
            input.peer_identity_fingerprint,
            input.result,
            Ed25519Signature::new([0; 64]),
        );
        let signature = self.ledger.identity.sign(commit.signing_input().as_slice());
        Ok(commit.with_signature(signature))
    }

    /// Atomically advances `ledger.state` to the head produced by `commit`
    /// (design section 12.3, steps 9-10): the commit must chain exactly to
    /// the head re-read under the lock, the new root is
    /// [`ledger_root_of`], and the state file is replaced atomically and
    /// synchronized. Consumes the session so the lock is released.
    pub fn advance(self, commit: &LedgerCommit) -> Result<(), AuditLedgerError> {
        let expected_sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(AuditLedgerError::AuditLedgerInvalid)?;
        if commit.sequence() != expected_sequence || commit.previous_root() != &self.head.root {
            return Err(AuditLedgerError::AuditLedgerConflict);
        }
        let new_head = LedgerHead {
            sequence: expected_sequence,
            root: ledger_root_of(commit),
        };
        write_ledger_state_atomic(&self.ledger.root, &new_head)?;
        self.ledger.head = new_head;
        Ok(())
    }
}

/// Computes the ledger root produced by a commit: the SHA-256 of the exact
/// persistent-identity-signed commit bytes (the domain label plus all commit
/// fields except the signature).
#[must_use]
pub fn ledger_root_of(commit: &LedgerCommit) -> LedgerRoot {
    LedgerRoot::new(Sha256::digest(commit.signing_input().as_slice()).into())
}

/// The exclusive lock guard: holds the `ledger.lock` file open and locked
/// and releases it on drop.
struct LedgerLockGuard {
    file: File,
}

impl Drop for LedgerLockGuard {
    fn drop(&mut self) {
        // The calls are fully qualified because `std::fs::File` gained its
        // own `lock`/`unlock` methods after the declared MSRV (1.88); the
        // `fs4` cross-process locking trait must always win.
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

/// Opens (or exclusively creates) `ledger.lock` and takes the blocking
/// exclusive cross-process lock.
fn acquire_ledger_lock(root: &Path) -> Result<LedgerLockGuard, AuditLedgerError> {
    let file = open_lock_file(root)?;
    fs4::FileExt::lock(&file).map_err(AuditLedgerError::LockFailed)?;
    Ok(LedgerLockGuard { file })
}

/// Opens the lock file, exclusively creating it (with `0600` permissions at
/// creation) when it does not exist. An existing lock file must be a
/// regular file, not a symlink, with protected permissions (section 11.1).
fn open_lock_file(root: &Path) -> Result<File, AuditLedgerError> {
    let path = root.join(identity::LEDGER_LOCK_FILE_NAME);
    for _attempt in 0..LOCK_CREATE_ATTEMPTS {
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                    return Err(AuditLedgerError::AuditLedgerPermissions);
                }
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(AuditLedgerError::LockFailed)?;
                if let Err(error) = SystemSecretFilePolicy.validate_existing(&path, &file) {
                    #[cfg(windows)]
                    if matches!(&error, SecretFileError::Insecure)
                        && _attempt + 1 < LOCK_CREATE_ATTEMPTS
                    {
                        // A competing creator may still be applying the
                        // protected DACL. The inherited ACL is already
                        // trusted-only because the audit root is protected;
                        // validation still requires the final protected ACL.
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    return Err(map_lock_policy(error));
                }
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.read(true).write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                match options.open(&path) {
                    Ok(file) => {
                        if let Err(error) = SystemSecretFilePolicy.protect_new(&path, &file) {
                            drop(file);
                            let _ = fs::remove_file(&path);
                            return Err(map_lock_policy(error));
                        }
                        return Ok(file);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(AuditLedgerError::LockFailed(error)),
                }
            }
            Err(error) => return Err(AuditLedgerError::LockFailed(error)),
        }
    }
    Err(AuditLedgerError::LockFailed(io::Error::new(
        io::ErrorKind::TimedOut,
        "the ledger lock file could not be created",
    )))
}

/// Loads `ledger.state`, or atomically creates the genesis state on first
/// use. An existing state file is never overwritten silently: it must parse
/// and validate or the open fails.
fn load_or_create_state(root: &Path) -> Result<LedgerHead, AuditLedgerError> {
    let path = root.join(identity::LEDGER_STATE_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_ledger_state(&path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let genesis = LedgerHead::genesis();
            write_ledger_state_atomic(root, &genesis)?;
            Ok(genesis)
        }
        Err(error) => Err(AuditLedgerError::StateReadFailed(error)),
    }
}

fn read_ledger_state(path: &Path) -> Result<LedgerHead, AuditLedgerError> {
    let meta = fs::symlink_metadata(path).map_err(AuditLedgerError::StateReadFailed)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(AuditLedgerError::AuditLedgerPermissions);
    }
    if meta.len() != LEDGER_STATE_LEN as u64 {
        return Err(AuditLedgerError::AuditLedgerInvalid);
    }
    let mut bytes = [0_u8; LEDGER_STATE_LEN];
    let mut file = File::open(path).map_err(AuditLedgerError::StateReadFailed)?;
    SystemSecretFilePolicy
        .validate_existing(path, &file)
        .map_err(map_state_policy)?;
    file.read_exact(&mut bytes)
        .map_err(AuditLedgerError::StateReadFailed)?;
    decode_ledger_state(&bytes)
}

fn decode_ledger_state(bytes: &[u8]) -> Result<LedgerHead, AuditLedgerError> {
    let bytes: [u8; LEDGER_STATE_LEN] = bytes
        .try_into()
        .map_err(|_| AuditLedgerError::AuditLedgerInvalid)?;
    if bytes[..8] != LEDGER_STATE_MAGIC {
        return Err(AuditLedgerError::AuditLedgerInvalid);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != LEDGER_STATE_VERSION {
        return Err(AuditLedgerError::AuditLedgerInvalid);
    }
    let checksum = Sha256::digest(&bytes[..LEDGER_STATE_CHECKSUM_OFFSET]);
    if checksum.as_slice() != &bytes[LEDGER_STATE_CHECKSUM_OFFSET..] {
        return Err(AuditLedgerError::AuditLedgerInvalid);
    }
    let sequence = u64::from_be_bytes(bytes[10..18].try_into().expect("fixed eight-byte slice"));
    let mut root = [0_u8; 32];
    root.copy_from_slice(&bytes[18..50]);
    Ok(LedgerHead {
        sequence,
        root: LedgerRoot::new(root),
    })
}

fn encode_ledger_state(head: &LedgerHead) -> [u8; LEDGER_STATE_LEN] {
    let mut bytes = [0_u8; LEDGER_STATE_LEN];
    bytes[..8].copy_from_slice(&LEDGER_STATE_MAGIC);
    bytes[8..10].copy_from_slice(&LEDGER_STATE_VERSION.to_be_bytes());
    bytes[10..18].copy_from_slice(&head.sequence.to_be_bytes());
    bytes[18..50].copy_from_slice(head.root.as_bytes());
    let checksum = Sha256::digest(&bytes[..LEDGER_STATE_CHECKSUM_OFFSET]);
    bytes[LEDGER_STATE_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    bytes
}

/// Atomically replaces `ledger.state` with a new head: write a private
/// temporary file, sync it, rename it over `ledger.state` and sync the
/// parent directory on Unix (design section 12.3, steps 9-10). The caller
/// must hold the ledger lock.
fn write_ledger_state_atomic(root: &Path, head: &LedgerHead) -> Result<(), AuditLedgerError> {
    let state_path = root.join(identity::LEDGER_STATE_FILE_NAME);
    let mut temporary = tempfile::Builder::new()
        .prefix(".ledger.state.")
        .tempfile_in(root)
        .map_err(AuditLedgerError::AuditLedgerCommitFailed)?;
    SystemSecretFilePolicy
        .protect_new(temporary.path(), temporary.as_file())
        .map_err(map_commit_policy)?;
    temporary
        .write_all(&encode_ledger_state(head))
        .map_err(AuditLedgerError::AuditLedgerCommitFailed)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(AuditLedgerError::AuditLedgerCommitFailed)?;
    let file = temporary
        .persist(&state_path)
        .map_err(|error| AuditLedgerError::AuditLedgerCommitFailed(error.error))?;
    SystemSecretFilePolicy
        .validate_existing(&state_path, &file)
        .map_err(map_commit_policy)?;
    #[cfg(unix)]
    {
        fs::File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(AuditLedgerError::AuditLedgerCommitFailed)?;
    }
    Ok(())
}

/// Scans `records/` for pending completed records and advances the ledger
/// when exactly one legal candidate connects directly to the head
/// (design section 12.4). Conflicts, forks and illegal previous roots reject
/// new sessions; interrupted, tampered and foreign-signed records cannot
/// enter the ledger and are skipped.
fn recover_pending_records(
    root: &Path,
    identity: &AuditIdentity,
    head: LedgerHead,
) -> Result<LedgerHead, AuditLedgerError> {
    let entries = match fs::read_dir(root.join(identity::RECORDS_DIR_NAME)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(head),
        Err(error) => return Err(AuditLedgerError::RecordReadFailed(error)),
    };
    let mut candidates: Vec<LedgerCommit> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(AuditLedgerError::RecordReadFailed)?;
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|extension| extension == RECORD_EXTENSION)
        {
            continue;
        }
        if let Some(commit) = inspect_pending_record(&path, identity, head)? {
            candidates.push(commit);
        }
    }
    match candidates.len() {
        0 => Ok(head),
        1 => {
            let new_sequence = head
                .sequence
                .checked_add(1)
                .ok_or(AuditLedgerError::AuditLedgerInvalid)?;
            let new_head = LedgerHead {
                sequence: new_sequence,
                root: ledger_root_of(&candidates[0]),
            };
            write_ledger_state_atomic(root, &new_head)?;
            Ok(new_head)
        }
        _ => Err(AuditLedgerError::AuditLedgerConflict),
    }
}

/// Inspects one record file as a potential pending commit, returning the
/// commit when it is a legal candidate that connects directly to the head.
///
/// The record must be a complete `.yonaudit` container: a parseable footer
/// (located by scanning a bounded tail for the footer magic) whose final
/// container digest matches the whole prefix, a commit signed by the local
/// persistent identity whose `sealed_record_digest` matches the sealed
/// prefix, and a chain position of exactly `head + 1` with
/// `previous_root == head.root`. Legal commits at other chain positions
/// fail closed ([`AuditLedgerError::AuditLedgerConflict`]).
fn inspect_pending_record(
    path: &Path,
    identity: &AuditIdentity,
    head: LedgerHead,
) -> Result<Option<LedgerCommit>, AuditLedgerError> {
    let meta = fs::symlink_metadata(path).map_err(AuditLedgerError::RecordReadFailed)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Ok(None);
    }
    let len = meta.len();
    if len < CONTAINER_HEADER_LEN as u64 {
        return Ok(None);
    }
    // Parse only a bounded tail of the file: everything a footer needs.
    let tail_len = usize::try_from(len.min(RECOVERY_TAIL_LEN as u64))
        .expect("the recovery tail is bounded and small");
    let mut file = File::open(path).map_err(AuditLedgerError::RecordReadFailed)?;
    SystemSecretFilePolicy
        .validate_existing(path, &file)
        .map_err(map_record_policy)?;
    file.seek(SeekFrom::End(-(tail_len as i64)))
        .map_err(AuditLedgerError::RecordReadFailed)?;
    let mut tail = [0_u8; RECOVERY_TAIL_LEN];
    file.read_exact(&mut tail[..tail_len])
        .map_err(AuditLedgerError::RecordReadFailed)?;
    // The footer magic cannot start inside a legal frame, so scanning the
    // tail for the last decodable footer is unambiguous: the real footer
    // always decodes, and a candidate inside a payload cannot both decode
    // and pass the digest verification below.
    let mut footer: Option<(usize, DecodedFooter)> = None;
    let mut scan = tail_len;
    while let Some(index) = tail[..scan]
        .iter()
        .rposition(|&byte| byte == FOOTER_MAGIC[0])
    {
        scan = index;
        if !tail[scan..].starts_with(&FOOTER_MAGIC) {
            continue;
        }
        if let Ok(decoded) = decode_footer(&tail[scan..]) {
            footer = Some((scan, decoded));
            break;
        }
    }
    let Some((footer_offset, decoded)) = footer else {
        return Ok(None);
    };
    let footer_start_abs = (len - tail_len as u64) as usize + footer_offset;
    let seal_end_abs = footer_start_abs + decoded.seal_end;
    let ledger_end_abs = footer_start_abs + decoded.ledger_end;
    let commit = &decoded.footer.ledger_commit;
    if !verify_record_digests(
        &mut file,
        seal_end_abs,
        ledger_end_abs,
        commit.sealed_record_digest(),
        &decoded.final_container_digest,
    )
    .map_err(AuditLedgerError::RecordReadFailed)?
    {
        return Ok(None);
    }
    // A commit not signed by the local persistent identity is not ours and
    // can never enter the ledger.
    if !identity.verify(commit.signing_input().as_slice(), commit.signature()) {
        return Ok(None);
    }
    let expected_sequence = head
        .sequence
        .checked_add(1)
        .ok_or(AuditLedgerError::AuditLedgerInvalid)?;
    match commit.sequence().cmp(&expected_sequence) {
        // A legally signed commit beyond the head means the state was rolled
        // back or a foreign chain was planted: fail closed.
        Ordering::Greater => Err(AuditLedgerError::AuditLedgerConflict),
        // Already committed; nothing to do.
        Ordering::Less => Ok(None),
        Ordering::Equal => {
            if commit.previous_root() != &head.root {
                // A direct child that does not chain to the head is a fork
                // or an illegal previous root.
                return Err(AuditLedgerError::AuditLedgerConflict);
            }
            Ok(Some(*commit))
        }
    }
}

/// Verifies the two prefix digests of a completed record in a single
/// streaming pass: the sealed record digest over `[0, seal_end)` and the
/// final container digest over `[0, ledger_end)`. The file must contain at
/// least `ledger_end` bytes; truncated files fail the check.
fn verify_record_digests(
    file: &mut File,
    seal_end: usize,
    ledger_end: usize,
    expected_sealed: &Digest32,
    expected_final: &Digest32,
) -> io::Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut seal_snapshot: Option<[u8; 32]> = None;
    let mut position = 0_usize;
    let mut buffer = [0_u8; RECOVERY_CHUNK];
    loop {
        if position == seal_end && seal_snapshot.is_none() {
            seal_snapshot = Some(hasher.clone().finalize().into());
        }
        let remaining = ledger_end.saturating_sub(position);
        if remaining == 0 {
            break;
        }
        let want = remaining.min(buffer.len());
        let read = file.read(&mut buffer[..want])?;
        if read == 0 {
            break;
        }
        let chunk_end = position + read;
        if seal_snapshot.is_none() && position < seal_end {
            let take = (seal_end - position).min(read);
            hasher.update(&buffer[..take]);
            if take < read {
                seal_snapshot = Some(hasher.clone().finalize().into());
                hasher.update(&buffer[take..read]);
            }
        } else {
            hasher.update(&buffer[..read]);
        }
        position = chunk_end;
    }
    if position != ledger_end {
        return Ok(false);
    }
    let sealed_ok = seal_snapshot.is_some_and(|digest| digest == *expected_sealed.as_bytes());
    if !sealed_ok {
        return Ok(false);
    }
    Ok(hasher.finalize().as_slice() == expected_final.as_bytes())
}

fn map_lock_policy(error: SecretFileError) -> AuditLedgerError {
    map_secret_policy(error, AuditLedgerError::LockFailed)
}

fn map_state_policy(error: SecretFileError) -> AuditLedgerError {
    map_secret_policy(error, AuditLedgerError::StateReadFailed)
}

fn map_record_policy(error: SecretFileError) -> AuditLedgerError {
    map_secret_policy(error, AuditLedgerError::RecordReadFailed)
}

fn map_commit_policy(error: SecretFileError) -> AuditLedgerError {
    map_secret_policy(error, AuditLedgerError::AuditLedgerCommitFailed)
}

fn map_secret_policy(
    error: SecretFileError,
    platform: impl FnOnce(io::Error) -> AuditLedgerError,
) -> AuditLedgerError {
    match error {
        SecretFileError::Insecure => AuditLedgerError::AuditLedgerPermissions,
        SecretFileError::Platform(error) => platform(error),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;
    use yonder_core::OsSecureRandom;
    use yonder_core::wire::audit::{
        AUDIT_FORMAT_VERSION, AuditHello, AuditNonce, AuditReady, AuditRole, AuthMode,
        BindingDigest, ChainHead, CommitmentDigest, IdentityFingerprint as Fingerprint,
        LocalRecordSeal, MANIFEST_SIGNATURE_LEN, ManifestEnding, ManifestSignature, SharedSnapshot,
        StreamSnapshot,
    };
    use yonder_core::wire::audit_container::{
        AuditContainerFooter, AuditContainerHeader, encode_footer_prefix,
    };

    fn test_root() -> PathBuf {
        tempdir().unwrap().path().join("audit")
    }

    fn test_commit_input(session_id: [u8; 32]) -> CommitInput {
        CommitInput::new(
            SessionId::new(session_id),
            Digest32::new([0x11; 32]),
            Digest32::new([0x22; 32]),
            Fingerprint::new([0x33; 32]),
            SessionResult::Normal,
        )
    }

    fn write_private_record(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        let file = File::open(path).unwrap();
        SystemSecretFilePolicy.protect_new(path, &file).unwrap();
    }

    #[test]
    fn first_open_initializes_the_ledger_layout() {
        let root = test_root();
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head(), LedgerHead::genesis());
        assert_eq!(ledger.head().sequence(), 0);
        assert_eq!(ledger.head().root(), LedgerHead::genesis().root());
        assert!(root.join(identity::IDENTITY_FILE_NAME).is_file());
        assert!(root.join(identity::LEDGER_STATE_FILE_NAME).is_file());
        assert!(root.join(identity::LEDGER_LOCK_FILE_NAME).is_file());
        assert!(!root.join(LEDGER_STATE_TMP_NAME).exists());
        // The state file round-trips through its codec.
        let bytes = fs::read(root.join(identity::LEDGER_STATE_FILE_NAME)).unwrap();
        assert_eq!(bytes.len(), LEDGER_STATE_LEN);
        assert_eq!(decode_ledger_state(&bytes).unwrap(), LedgerHead::genesis());
        // Reopening is stable and the lock was released (no blocking).
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head(), LedgerHead::genesis());
        let _second_handle = Ledger::open(&root, &mut OsSecureRandom).unwrap();
    }

    #[test]
    fn commit_inputs_debug_output_and_sequence_overflow_are_bounded() {
        let input = test_commit_input([0x31; 32]);
        assert_eq!(input.session_id(), SessionId::new([0x31; 32]));
        assert_eq!(input.manifest_digest(), Digest32::new([0x11; 32]));
        assert_eq!(input.sealed_record_digest(), Digest32::new([0x22; 32]));
        assert_eq!(
            input.peer_identity_fingerprint(),
            IdentityFingerprint::new([0x33; 32])
        );
        assert_eq!(input.result(), SessionResult::Normal);

        let root = test_root();
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let debug = format!("{ledger:?}");
        assert!(debug.contains("Ledger"));
        assert!(!debug.contains(root.to_string_lossy().as_ref()));

        let mut commit = ledger.begin_owned_commit().unwrap();
        assert_eq!(commit.head().sequence(), 0);
        commit.head.sequence = u64::MAX;
        assert!(matches!(
            commit.commit(&input),
            Err(AuditLedgerError::AuditLedgerInvalid)
        ));
        let ledger = commit.into_ledger();
        assert_eq!(ledger.head().sequence(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_policy_errors_map_to_their_fixed_ledger_categories() {
        for mapped in [
            map_lock_policy(SecretFileError::Insecure),
            map_state_policy(SecretFileError::Insecure),
            map_record_policy(SecretFileError::Insecure),
            map_commit_policy(SecretFileError::Insecure),
        ] {
            assert!(matches!(mapped, AuditLedgerError::AuditLedgerPermissions));
        }
        assert!(matches!(
            map_lock_policy(SecretFileError::Platform(io::Error::other("lock"))),
            AuditLedgerError::LockFailed(_)
        ));
        assert!(matches!(
            map_state_policy(SecretFileError::Platform(io::Error::other("state"))),
            AuditLedgerError::StateReadFailed(_)
        ));
        assert!(matches!(
            map_record_policy(SecretFileError::Platform(io::Error::other("record"))),
            AuditLedgerError::RecordReadFailed(_)
        ));
        assert!(matches!(
            map_commit_policy(SecretFileError::Platform(io::Error::other("commit"))),
            AuditLedgerError::AuditLedgerCommitFailed(_)
        ));
    }

    #[test]
    fn commits_chain_and_advance_the_head() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        assert_eq!(session.head(), LedgerHead::genesis());
        let first = session.commit(&test_commit_input([1; 32])).unwrap();
        assert_eq!(first.sequence(), 1);
        assert_eq!(first.previous_root(), &LedgerHead::genesis().root());
        session.advance(&first).unwrap();
        assert_eq!(ledger.head().sequence(), 1);
        assert_eq!(ledger.head().root(), ledger_root_of(&first));

        // A second session chains from the new head.
        let session = ledger.begin_commit().unwrap();
        let second = session.commit(&test_commit_input([2; 32])).unwrap();
        assert_eq!(second.sequence(), 2);
        assert_eq!(second.previous_root(), &ledger_root_of(&first));
        session.advance(&second).unwrap();
        assert_eq!(ledger.head().sequence(), 2);
        assert_eq!(ledger.head().root(), ledger_root_of(&second));

        // Reopening loads the persisted head.
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head().sequence(), 2);
        assert_eq!(ledger.head().root(), ledger_root_of(&second));
    }

    #[test]
    fn ledger_commits_are_signed_by_the_persistent_identity() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        let commit = session.commit(&test_commit_input([3; 32])).unwrap();
        drop(session);
        assert!(
            ledger
                .identity()
                .verify(commit.signing_input().as_slice(), commit.signature())
        );
        // The root is the digest of exactly those signed bytes.
        assert_eq!(
            ledger_root_of(&commit),
            LedgerRoot::new(Sha256::digest(commit.signing_input().as_slice()).into())
        );
    }

    #[test]
    fn concurrent_sessions_serialize_commits_without_forking() {
        let root = test_root();
        let mut handles = Vec::new();
        for index in 0..2_u8 {
            let root = root.clone();
            handles.push(std::thread::spawn(move || {
                let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
                let session = ledger.begin_commit().unwrap();
                let commit = session
                    .commit(&test_commit_input([0x10 + index; 32]))
                    .unwrap();
                let sequence = commit.sequence();
                session.advance(&commit).unwrap();
                (sequence, commit)
            }));
        }
        let commits: Vec<(u64, LedgerCommit)> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let (first, second) = if commits[0].0 < commits[1].0 {
            (&commits[0].1, &commits[1].1)
        } else {
            (&commits[1].1, &commits[0].1)
        };
        // Exactly one commit per sequence, chained without a fork.
        assert_eq!(first.sequence(), 1);
        assert_eq!(second.sequence(), 2);
        assert_eq!(second.previous_root(), &ledger_root_of(first));
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head().sequence(), 2);
        assert_eq!(ledger.head().root(), ledger_root_of(second));
    }

    #[test]
    fn concurrent_first_open_creates_one_identity() {
        let root = test_root();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let root = root.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                Ledger::open(&root, &mut OsSecureRandom).unwrap()
            }));
        }
        let ledgers: Vec<Ledger> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        // Both openers observe the same exclusive identity.
        assert_eq!(
            ledgers[0].identity().public_key(),
            ledgers[1].identity().public_key()
        );
        let again = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(
            again.identity().public_key(),
            ledgers[0].identity().public_key()
        );
    }

    #[test]
    fn crash_recovery_advances_the_single_pending_record() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        let head = session.head();
        drop(session);
        let (record, commit) =
            build_pending_record(ledger.identity(), head, SessionId::new([7; 32]));
        // Simulated crash: the audit file was synced with its footer, but
        // ledger.state was never advanced.
        write_private_record(
            &root
                .join(identity::RECORDS_DIR_NAME)
                .join("abc.controller.yonaudit"),
            &record,
        );
        // The next lock holder recovers exactly this single candidate.
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head().sequence(), 1);
        assert_eq!(ledger.head().root(), ledger_root_of(&commit));
        // A further open finds nothing pending.
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head().sequence(), 1);
    }

    #[test]
    fn crash_recovery_rejects_multiple_conflicting_candidates() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        let head = session.head();
        drop(session);
        let (record_a, _) = build_pending_record(ledger.identity(), head, SessionId::new([1; 32]));
        let (record_b, _) = build_pending_record(ledger.identity(), head, SessionId::new([2; 32]));
        let records = root.join(identity::RECORDS_DIR_NAME);
        write_private_record(&records.join("a.controller.yonaudit"), &record_a);
        write_private_record(&records.join("b.controller.yonaudit"), &record_b);
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerConflict)
        ));
    }

    #[test]
    fn crash_recovery_rejects_a_record_that_does_not_link_to_the_head() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        let head = session.head();
        drop(session);
        // A legally signed commit whose previous root is not the head root:
        // a fork with an illegal previous root.
        let forked_head = LedgerHead {
            sequence: head.sequence(),
            root: LedgerRoot::new([0xAA; 32]),
        };
        let (record, _) =
            build_pending_record(ledger.identity(), forked_head, SessionId::new([3; 32]));
        write_private_record(
            &root
                .join(identity::RECORDS_DIR_NAME)
                .join("fork.controller.yonaudit"),
            &record,
        );
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerConflict)
        ));
    }

    #[test]
    fn crash_recovery_skips_records_that_cannot_enter_the_ledger() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        let head = session.head();
        drop(session);
        let records = root.join(identity::RECORDS_DIR_NAME);

        // A truncated record with no footer is not a candidate.
        let truncated = AuditContainerHeader::new(
            AuditRole::Controller,
            SessionId::new([1; 32]),
            ledger.identity().public_key(),
            yonder_core::wire::audit::Ed25519PublicKey::new([2; 32]),
            yonder_core::wire::audit::Ed25519PublicKey::new([3; 32]),
            yonder_core::wire::audit::Ed25519PublicKey::new([4; 32]),
            7,
            LedgerRoot::new([0; 32]),
            1_700_000_000,
            AuthMode::Enterprise,
            Digest32::new([5; 32]),
            test_hello(),
            test_ready(),
        )
        .encode()
        .as_slice()
        .to_vec();
        write_private_record(&records.join("truncated.controller.yonaudit"), &truncated);

        // A tampered record (final digest mismatch) is not a candidate.
        let (mut tampered, _) =
            build_pending_record(ledger.identity(), head, SessionId::new([4; 32]));
        tampered[CONTAINER_HEADER_LEN - 1] ^= 0x01;
        write_private_record(&records.join("tampered.controller.yonaudit"), &tampered);

        // A record committed by a foreign identity is not a candidate.
        let foreign = AuditIdentity::generate(&mut OsSecureRandom).unwrap();
        let (foreign_record, _) = build_pending_record(&foreign, head, SessionId::new([5; 32]));
        write_private_record(
            &records.join("foreign.controller.yonaudit"),
            &foreign_record,
        );

        // Recovery skips all of them and keeps the head untouched.
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head(), head);

        // A record that was already committed is skipped, never replayed.
        let (committed, _) = build_pending_record(ledger.identity(), head, SessionId::new([6; 32]));
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        session.advance(&committed_commit(&committed)).unwrap();
        write_private_record(&records.join("committed.controller.yonaudit"), &committed);
        let ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(ledger.head().sequence(), 1);
    }

    /// Extracts the commit embedded in a record built by
    /// `build_pending_record` by re-signing the same fields; used only to
    /// advance the ledger with a commit matching a previously built record.
    fn committed_commit(record: &[u8]) -> LedgerCommit {
        // Rebuild the commit deterministically: the record layout is
        // header ++ prefix ++ digest, and the commit sits at a fixed
        // offset from the end (2-byte length prefix + 233 bytes).
        let tail = &record[record.len() - 32 - 2 - 233..];
        let commit_len = usize::from(u16::from_be_bytes([tail[0], tail[1]]));
        assert_eq!(commit_len, 233);
        LedgerCommit::decode_payload(&tail[2..2 + commit_len]).unwrap()
    }

    #[test]
    fn corrupted_ledger_state_is_rejected_and_never_silently_replaced() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        let commit = session.commit(&test_commit_input([8; 32])).unwrap();
        session.advance(&commit).unwrap();
        let path = root.join(identity::LEDGER_STATE_FILE_NAME);

        // Checksum mismatch.
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerInvalid)
        ));

        // Wrong magic.
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] = b'X';
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerInvalid)
        ));

        // Truncated state.
        fs::write(&path, [0_u8; 10]).unwrap();
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerInvalid)
        ));
    }

    #[test]
    fn atomic_state_replace_leaves_no_temporary_files() {
        let root = test_root();
        let mut ledger = Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let session = ledger.begin_commit().unwrap();
        let commit = session.commit(&test_commit_input([9; 32])).unwrap();
        session.advance(&commit).unwrap();
        assert!(!root.join(LEDGER_STATE_TMP_NAME).exists());
        let bytes = fs::read(root.join(identity::LEDGER_STATE_FILE_NAME)).unwrap();
        assert_eq!(bytes.len(), LEDGER_STATE_LEN);
        let head = decode_ledger_state(&bytes).unwrap();
        assert_eq!(head.sequence(), 1);
        assert_eq!(head.root(), ledger_root_of(&commit));
    }

    #[cfg(unix)]
    #[test]
    fn ledger_state_and_lock_permission_anomalies_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempdir().unwrap();
        let root = dir.path().join("audit");
        Ledger::open(&root, &mut OsSecureRandom).unwrap();

        // A wrongly-permissioned state file is rejected.
        fs::set_permissions(
            root.join(identity::LEDGER_STATE_FILE_NAME),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerPermissions)
        ));
        fs::set_permissions(
            root.join(identity::LEDGER_STATE_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        // A wrongly-permissioned lock file is rejected.
        fs::set_permissions(
            root.join(identity::LEDGER_LOCK_FILE_NAME),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerPermissions)
        ));
        fs::set_permissions(
            root.join(identity::LEDGER_LOCK_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        // A symlinked state file is never followed.
        let state = root.join(identity::LEDGER_STATE_FILE_NAME);
        fs::remove_file(&state).unwrap();
        symlink(dir.path().join("victim-state"), &state).unwrap();
        fs::write(dir.path().join("victim-state"), [0_u8; 82]).unwrap();
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerPermissions)
        ));

        // A symlinked lock file is never followed.
        fs::remove_file(&state).unwrap();
        let lock = root.join(identity::LEDGER_LOCK_FILE_NAME);
        fs::remove_file(&lock).unwrap();
        symlink(dir.path().join("victim-lock"), &lock).unwrap();
        fs::write(dir.path().join("victim-lock"), [0_u8; 8]).unwrap();
        assert!(matches!(
            Ledger::open(&root, &mut OsSecureRandom),
            Err(AuditLedgerError::AuditLedgerPermissions)
        ));
    }

    // ------------------------------------------------------------------
    // Record building helpers: construct a complete `.yonaudit` container
    // whose digests are self-consistent with an embedded signed commit.
    // ------------------------------------------------------------------

    fn test_hello() -> AuditHello {
        AuditHello::new(
            AuditRole::Controller,
            yonder_core::wire::audit::Ed25519PublicKey::new([1; 32]),
            yonder_core::wire::audit::Ed25519PublicKey::new([2; 32]),
            AuditNonce::new([3; 32]),
            7,
            LedgerRoot::new([0; 32]),
            BindingDigest::new([4; 32]),
            AUDIT_FORMAT_VERSION,
            CommitmentDigest::new([5; 32]),
            Ed25519Signature::new([6; 64]),
        )
    }

    fn test_ready() -> AuditReady {
        AuditReady::new(
            SessionId::new([1; 32]),
            Digest32::new([2; 32]),
            AUDIT_FORMAT_VERSION,
            Ed25519Signature::new([3; 64]),
        )
    }

    fn test_manifest() -> yonder_core::wire::audit::JointManifest {
        yonder_core::wire::audit::JointManifest::new(
            AUDIT_FORMAT_VERSION,
            SessionId::new([1; 32]),
            Fingerprint::new([2; 32]),
            Fingerprint::new([3; 32]),
            yonder_core::wire::audit::Ed25519PublicKey::new([4; 32]),
            yonder_core::wire::audit::Ed25519PublicKey::new([5; 32]),
            BindingDigest::new([6; 32]),
            Digest32::new([7; 32]),
            SharedSnapshot::new([
                StreamSnapshot::new(10, ChainHead::new([0; 32])),
                StreamSnapshot::new(20, ChainHead::new([0; 32])),
                StreamSnapshot::new(30, ChainHead::new([0; 32])),
                StreamSnapshot::new(40, ChainHead::new([0; 32])),
            ]),
            ManifestEnding::ShellExit(0),
            true,
            9,
        )
    }

    fn test_seal() -> LocalRecordSeal {
        LocalRecordSeal::new(
            SessionId::new([1; 32]),
            AuditRole::Controller,
            ChainHead::new([0; 32]),
            12,
            [ChainHead::new([0; 32]); 4],
            Digest32::new([2; 32]),
            Digest32::new([3; 32]),
            Ed25519Signature::new([4; 64]),
        )
    }

    /// Builds a complete container that embeds `commit`-shaped content: the
    /// header, the footer prefix (manifest, both session signatures, the
    /// seal and the commit) and the final container digest. The commit's
    /// `sealed_record_digest` covers everything before the commit
    /// (header, manifest, signatures, seal), so the record is exactly what
    /// a synced-but-not-advanced session leaves behind.
    fn build_pending_record(
        identity: &AuditIdentity,
        head: LedgerHead,
        session_id: SessionId,
    ) -> (Vec<u8>, LedgerCommit) {
        let manifest = test_manifest();
        let seal = test_seal();
        let header = AuditContainerHeader::new(
            AuditRole::Controller,
            SessionId::new([1; 32]),
            identity.public_key(),
            yonder_core::wire::audit::Ed25519PublicKey::new([2; 32]),
            yonder_core::wire::audit::Ed25519PublicKey::new([3; 32]),
            yonder_core::wire::audit::Ed25519PublicKey::new([4; 32]),
            7,
            LedgerRoot::new([0; 32]),
            1_700_000_000,
            AuthMode::Enterprise,
            Digest32::new([5; 32]),
            test_hello(),
            test_ready(),
        )
        .with_header_signature(Ed25519Signature::new([9; 64]));
        let header_bytes = header.encode().as_slice().to_vec();
        // The seal boundary depends only on the fixed component sizes.
        let manifest_len = manifest.encode_payload().unwrap().as_slice().len();
        let seal_len = seal.encode_payload().as_slice().len();
        let seal_rel =
            FOOTER_MAGIC.len() + 2 + manifest_len + (2 + MANIFEST_SIGNATURE_LEN) * 2 + 2 + seal_len;
        let placeholder = LedgerCommit::new(
            0,
            LedgerRoot::new([0; 32]),
            SessionId::new([0; 32]),
            Digest32::new([0; 32]),
            Digest32::new([0; 32]),
            Fingerprint::new([0; 32]),
            SessionResult::Normal,
            Ed25519Signature::new([0; 64]),
        );
        let prefix = encode_footer_prefix(&AuditContainerFooter {
            manifest: manifest.clone(),
            controller_session_signature: ManifestSignature::new(Ed25519Signature::new([6; 64])),
            host_session_signature: ManifestSignature::new(Ed25519Signature::new([7; 64])),
            seal,
            ledger_commit: placeholder,
        })
        .unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&header_bytes);
        hasher.update(&prefix.as_slice()[..seal_rel]);
        let sealed_digest = Digest32::new(hasher.finalize().into());
        let mut commit = LedgerCommit::new(
            head.sequence() + 1,
            head.root(),
            session_id,
            Digest32::new([0x44; 32]),
            sealed_digest,
            Fingerprint::new([0x55; 32]),
            SessionResult::Normal,
            Ed25519Signature::new([0; 64]),
        );
        let signature = identity.sign(commit.signing_input().as_slice());
        commit = commit.with_signature(signature);
        let full_prefix = encode_footer_prefix(&AuditContainerFooter {
            manifest,
            controller_session_signature: ManifestSignature::new(Ed25519Signature::new([6; 64])),
            host_session_signature: ManifestSignature::new(Ed25519Signature::new([7; 64])),
            seal,
            ledger_commit: commit,
        })
        .unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&header_bytes);
        hasher.update(full_prefix.as_slice());
        let mut record = header_bytes;
        record.extend_from_slice(full_prefix.as_slice());
        record.extend_from_slice(&hasher.finalize());
        (record, commit)
    }
}
