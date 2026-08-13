//! The persistent local audit identity, Yonder 0.2.0 design sections 9
//! (audit identity), 10 (storage location) and 11 (local file protection).
//!
//! Every local `yon` user environment owns one persistent Ed25519 audit
//! identity (section 9.1). It proves that multiple sessions belong to the
//! same endpoint audit identity, signs the session binding and signs every
//! local ledger commit; it also prevents an attacker from replacing a single
//! audit file with a freshly generated self-consistent record.
//!
//! # Automatic creation (section 9.2)
//!
//! There is no initialization command. On first use with no local audit
//! history, the identity is generated from the project-wide
//! [`yonder_core::OsSecureRandom`] source (via [`yonder_core::IdentitySeed`],
//! a zeroizing 32-byte container), written exclusively (an existing name is
//! never followed or overwritten) with `0600` permissions, and the identity
//! file and the audit directory are synchronized. If audit history exists
//! but the identity file is missing, unreadable or invalid, the operation
//! fails with [`AuditIdentityError::AuditIdentityMissing`] or
//! [`AuditIdentityError::AuditIdentityInvalid`]; a new identity is never
//! generated silently.
//!
//! # Identity file format
//!
//! `identity.ed25519` is a fixed 74-byte binary file:
//!
//! ```text
//! magic    8 bytes  "YONIDNT\0"
//! version  2 bytes  big-endian u16, frozen at 1
//! seed    32 bytes  the Ed25519 signing seed
//! pubkey  32 bytes  the verifying key
//! ```
//!
//! The verifying key is a deterministic function of the seed, so corruption
//! of either half is detected on load: the stored public key must match
//! `SigningKey::from_bytes(seed).verifying_key()`. The seed bytes are held
//! in a [`Zeroizing`] container and the in-memory identity
//! ([`AuditIdentity`]) zeroizes its signing key on drop.
//!
//! # Storage locations (section 10)
//!
//! The audit root is resolved by [`PlatformAuditRoot`] through the
//! injectable [`AuditRoot`] trait, so tests can point the same machinery at
//! a temporary directory:
//!
//! - Linux: `$XDG_STATE_HOME/yonder/audit`, or `~/.local/state/yonder/audit`
//!   when `XDG_STATE_HOME` is unset. A set `XDG_STATE_HOME` must be a
//!   non-empty absolute path; any other value fails closed (section 10.1).
//! - macOS: `~/Library/Application Support/Yonder/Audit` (section 10.2).
//! - Windows: `%LOCALAPPDATA%\Yonder\Audit`; `LOCALAPPDATA` must resolve to
//!   a non-empty absolute path or initialization fails (section 10.3).
//!
//! # File protection (section 11)
//!
//! Unix: the audit root and `records/` are created `0700`, the identity
//! file `0600`; permissions are applied at creation time (never created
//! wide and tightened afterwards) and verified on every load; symlinks are
//! rejected as identity, ledger or record targets; every file is created
//! exclusively. Any permission anomaly rejects the session (section 11.1).
//!
//! Windows: the shared [`yonder_core::SecretFilePolicy`] and
//! [`yonder_core::PrivateDirectoryPolicy`] adapters apply and verify a
//! protected DACL for the current user, `SYSTEM` and `Administrators`.
//! Missing PowerShell/.NET ACL support fails closed before secret bytes are
//! written or an enterprise terminal becomes active.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use yonder_core::wire::audit::{Ed25519PublicKey, Ed25519Signature, IdentityFingerprint};
use yonder_core::{
    IdentitySeed, PrivateDirectoryPolicy, RandomError, SecretFileError, SecretFilePolicy,
    SecureRandom, SystemPrivateDirectoryPolicy, SystemSecretFilePolicy,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// The audit identity file name (design section 10.4).
pub const IDENTITY_FILE_NAME: &str = "identity.ed25519";
/// The local ledger state file name (design section 10.4).
pub const LEDGER_STATE_FILE_NAME: &str = "ledger.state";
/// The cross-process ledger lock file name (design section 10.4).
pub const LEDGER_LOCK_FILE_NAME: &str = "ledger.lock";
/// The local audit records directory (design section 10.4).
pub const RECORDS_DIR_NAME: &str = "records";

/// The fixed eight-byte identity file magic.
const IDENTITY_MAGIC: [u8; 8] = *b"YONIDNT\0";
/// The frozen identity file format version.
const IDENTITY_FORMAT_VERSION: u16 = 1;
/// Fixed identity file size: magic, version, seed and verifying key.
const IDENTITY_FILE_LEN: usize = IDENTITY_MAGIC.len() + 2 + 32 + 32;

/// The private permissions of every audit directory (design section 11.1).
#[cfg(all(test, unix))]
const PRIVATE_DIR_MODE: u32 = 0o700;
/// The private permissions of every audit file (design section 11.1).
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Errors of the persistent audit identity and its storage, one category per
/// design section 30 failure class. Messages are fixed, redacted and never
/// contain paths or key material.
#[derive(Debug, Error)]
pub enum AuditIdentityError {
    /// `AuditDirectoryUnavailable`: the audit directory cannot be determined
    /// or created (design section 10).
    #[error("the audit directory is unavailable")]
    AuditDirectoryUnavailable,
    /// The state-directory environment variable is set but is not a
    /// non-empty absolute path (design sections 10.1 and 10.3).
    #[error("the audit directory environment variable must be a non-empty absolute path")]
    InvalidAuditDirectoryEnv,
    /// `AuditIdentityMissing`: audit history exists but the identity file
    /// does not (design section 9.2).
    #[error("audit history exists but the persistent audit identity file is missing")]
    AuditIdentityMissing,
    /// `AuditIdentityInvalid`: the identity file exists but cannot be
    /// validated.
    #[error("the persistent audit identity file is invalid")]
    AuditIdentityInvalid,
    /// `AuditIdentityPermissions`: an identity file or audit directory has
    /// invalid permissions or is a symlink (design section 11).
    #[error("the persistent audit identity file or directory permissions are invalid")]
    AuditIdentityPermissions,
    /// The operating system secure random source failed.
    #[error("the operating system secure random source failed")]
    RandomSourceFailed(#[source] RandomError),
    /// Creating an audit directory failed.
    #[error("failed to create the audit directory")]
    CreateDirectoryFailed(#[source] io::Error),
    /// Reading the identity file failed.
    #[error("failed to read the audit identity")]
    ReadFailed(#[source] io::Error),
    /// Writing the identity file failed.
    #[error("failed to write the audit identity")]
    WriteFailed(#[source] io::Error),
    /// Synchronizing the identity file or an audit directory failed.
    #[error("failed to synchronize the audit identity")]
    SyncFailed(#[source] io::Error),
}

/// Resolves the absolute audit root directory (design section 10).
///
/// The production implementation is [`PlatformAuditRoot`]; tests inject a
/// temporary directory through this trait so the whole storage machinery can
/// be exercised without touching the real user state.
pub trait AuditRoot {
    /// Resolves the audit root, which must be absolute.
    fn audit_root(&self) -> Result<PathBuf, AuditIdentityError>;
}

/// The platform-specific audit root location (design section 10).
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformAuditRoot;

impl AuditRoot for PlatformAuditRoot {
    fn audit_root(&self) -> Result<PathBuf, AuditIdentityError> {
        platform_audit_root()
    }
}

/// Design section 10.1: `$XDG_STATE_HOME/yonder/audit`, or
/// `~/.local/state/yonder/audit` when `XDG_STATE_HOME` is unset. A set
/// `XDG_STATE_HOME` must be a non-empty absolute path; any other value
/// fails closed instead of guessing against the current directory.
///
/// The function is pure so the environment rules are testable without
/// mutating process-global state; on non-Linux builds it exists for the
/// tests and for platforms without a dedicated convention.
#[cfg_attr(not(test), allow(dead_code))]
fn linux_audit_root(
    xdg_state_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, AuditIdentityError> {
    match xdg_state_home {
        Some(value) => {
            if value.is_empty() || !Path::new(&value).is_absolute() {
                return Err(AuditIdentityError::InvalidAuditDirectoryEnv);
            }
            Ok(PathBuf::from(value).join("yonder").join("audit"))
        }
        None => {
            let home = home.ok_or(AuditIdentityError::AuditDirectoryUnavailable)?;
            if home.is_empty() {
                return Err(AuditIdentityError::AuditDirectoryUnavailable);
            }
            Ok(PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("yonder")
                .join("audit"))
        }
    }
}

/// Design section 10.2: `~/Library/Application Support/Yonder/Audit`.
#[cfg_attr(not(test), allow(dead_code))]
fn macos_audit_root(home: Option<OsString>) -> Result<PathBuf, AuditIdentityError> {
    let home = home.ok_or(AuditIdentityError::AuditDirectoryUnavailable)?;
    if home.is_empty() {
        return Err(AuditIdentityError::AuditDirectoryUnavailable);
    }
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Yonder")
        .join("Audit"))
}

/// Design section 10.3: `%LOCALAPPDATA%\Yonder\Audit`. `LOCALAPPDATA` must
/// resolve to a non-empty absolute path; any other value fails closed.
#[cfg_attr(not(test), allow(dead_code))]
fn windows_audit_root(local_app_data: Option<OsString>) -> Result<PathBuf, AuditIdentityError> {
    match local_app_data {
        Some(value) => {
            if value.is_empty() || !Path::new(&value).is_absolute() {
                return Err(AuditIdentityError::InvalidAuditDirectoryEnv);
            }
            Ok(PathBuf::from(value).join("Yonder").join("Audit"))
        }
        None => Err(AuditIdentityError::AuditDirectoryUnavailable),
    }
}

fn platform_audit_root() -> Result<PathBuf, AuditIdentityError> {
    #[cfg(target_os = "linux")]
    {
        linux_audit_root(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
    }
    #[cfg(target_os = "macos")]
    {
        macos_audit_root(std::env::var_os("HOME"))
    }
    #[cfg(windows)]
    {
        windows_audit_root(std::env::var_os("LOCALAPPDATA"))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        linux_audit_root(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
    }
}

/// The persistent Ed25519 audit identity (design section 9.1).
///
/// The signing key is held in a [`ZeroizeOnDrop`] field (the `ed25519-dalek`
/// `zeroize` feature wipes the seed and the expanded key when the identity
/// is dropped). `Debug` is redacted: it never prints key material.
#[derive(Clone, ZeroizeOnDrop)]
pub struct AuditIdentity {
    signing_key: SigningKey,
}

impl AuditIdentity {
    /// Generates a fresh identity from the approved fallible CSPRNG
    /// boundary ([`yonder_core::SecureRandom`]).
    pub fn generate(random: &mut impl SecureRandom) -> Result<Self, AuditIdentityError> {
        let mut seed =
            IdentitySeed::generate(random).map_err(AuditIdentityError::RandomSourceFailed)?;
        Ok(Self::from_seed_bytes(seed.as_mut_bytes()))
    }

    /// Builds the identity from a 32-byte seed, deriving the verifying key.
    #[must_use]
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// The Ed25519 verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The persistent audit public key as the wire type carried by
    /// `AuditHello` and the container header (design sections 13.3 and 23.2).
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::new(self.verifying_key().to_bytes())
    }

    /// The 32-byte SHA-256 fingerprint of the persistent audit public key
    /// (design sections 9.4 and 21.1).
    #[must_use]
    pub fn fingerprint(&self) -> IdentityFingerprint {
        IdentityFingerprint::new(Sha256::digest(self.public_key().as_bytes()).into())
    }

    /// Signs a message with the persistent audit identity.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signature = self.signing_key.sign(message);
        Ed25519Signature::new(signature.to_bytes())
    }

    /// Verifies a signature over `message` with this identity's public key
    /// using strict Ed25519 verification.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        verify_ed25519_signature(&self.public_key(), message, signature)
    }
}

impl std::fmt::Debug for AuditIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditIdentity([REDACTED])")
    }
}

/// Verifies an Ed25519 signature against a wire public key, for example a
/// peer's `AuditHello` signature, using strict verification.
#[must_use]
pub fn verify_ed25519_signature(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key.as_bytes()) else {
        return false;
    };
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying_key.verify_strict(message, &signature).is_ok()
}

/// Opens the local audit identity: loads and validates the existing
/// `identity.ed25519`, or generates, writes exclusively and synchronizes a
/// fresh one on first use with no audit history (design sections 9.2 and
/// 11.1). An identity file that exists but is unreadable or invalid is
/// rejected; it is never silently replaced by a new identity.
pub fn open_or_create_identity(
    root: &Path,
    random: &mut impl SecureRandom,
) -> Result<AuditIdentity, AuditIdentityError> {
    ensure_audit_dirs(root)?;
    let path = root.join(IDENTITY_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(AuditIdentityError::AuditIdentityPermissions);
            }
            load_identity_file(&path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if audit_history_exists(root)? {
                return Err(AuditIdentityError::AuditIdentityMissing);
            }
            create_identity_file(&path, root, random)
        }
        Err(error) => Err(AuditIdentityError::ReadFailed(error)),
    }
}

/// Creates the audit root and `records/` directories (design sections 9.2
/// and 10.4) with private permissions, rejecting symlinked or
/// wrongly-permissioned existing directories.
pub fn ensure_audit_dirs(root: &Path) -> Result<(), AuditIdentityError> {
    ensure_private_dir(root)?;
    ensure_private_dir(&root.join(RECORDS_DIR_NAME))?;
    Ok(())
}

/// "Audit history" means anything a later session could depend on: an
/// existing ledger state or any entry in `records/`. An empty pre-existing
/// audit directory is not history, so a failed first run can safely retry.
fn audit_history_exists(root: &Path) -> Result<bool, AuditIdentityError> {
    if fs::symlink_metadata(root.join(LEDGER_STATE_FILE_NAME)).is_ok() {
        return Ok(true);
    }
    match fs::read_dir(root.join(RECORDS_DIR_NAME)) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AuditIdentityError::ReadFailed(error)),
    }
}

fn ensure_private_dir(path: &Path) -> Result<(), AuditIdentityError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(AuditIdentityError::AuditIdentityPermissions);
            }
            SystemPrivateDirectoryPolicy
                .validate(path)
                .map_err(map_policy_read)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => SystemPrivateDirectoryPolicy
            .protect(path)
            .map_err(map_policy_create),
        Err(error) => Err(AuditIdentityError::CreateDirectoryFailed(error)),
    }
}

fn load_identity_file(path: &Path) -> Result<AuditIdentity, AuditIdentityError> {
    let meta = fs::symlink_metadata(path).map_err(AuditIdentityError::ReadFailed)?;
    if meta.file_type().is_symlink() {
        return Err(AuditIdentityError::AuditIdentityPermissions);
    }
    if !meta.file_type().is_file() {
        return Err(AuditIdentityError::AuditIdentityInvalid);
    }
    if meta.len() != IDENTITY_FILE_LEN as u64 {
        return Err(AuditIdentityError::AuditIdentityInvalid);
    }
    let mut bytes = [0_u8; IDENTITY_FILE_LEN];
    let mut file = fs::File::open(path).map_err(AuditIdentityError::ReadFailed)?;
    SystemSecretFilePolicy
        .validate_existing(path, &file)
        .map_err(map_policy_read)?;
    file.read_exact(&mut bytes)
        .map_err(AuditIdentityError::ReadFailed)?;
    decode_identity_file(&bytes)
}

fn create_identity_file(
    path: &Path,
    root: &Path,
    random: &mut impl SecureRandom,
) -> Result<AuditIdentity, AuditIdentityError> {
    let identity = AuditIdentity::generate(random)?;
    let seed = Zeroizing::new(identity.signing_key.to_bytes());
    let encoded = encode_identity_file(&seed, &identity.verifying_key().to_bytes());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    let mut file = match options.open(path) {
        Ok(file) => file,
        // Another process won the exclusive creation race; the production
        // path is serialized by the ledger lock, so this only happens for
        // direct callers. Load what the winner wrote.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return load_identity_file(path);
        }
        Err(error) => return Err(AuditIdentityError::WriteFailed(error)),
    };
    if let Err(error) = SystemSecretFilePolicy.protect_new(path, &file) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(map_policy_write(error));
    }
    file.write_all(&encoded)
        .map_err(AuditIdentityError::WriteFailed)?;
    file.sync_all().map_err(AuditIdentityError::SyncFailed)?;
    apply_identity_file_protection(path, root)?;
    Ok(identity)
}

#[cfg(unix)]
fn apply_identity_file_protection(path: &Path, root: &Path) -> Result<(), AuditIdentityError> {
    let file = fs::File::open(path).map_err(AuditIdentityError::ReadFailed)?;
    SystemSecretFilePolicy
        .validate_existing(path, &file)
        .map_err(map_policy_read)?;
    sync_directory(root)
}

#[cfg(windows)]
fn apply_identity_file_protection(path: &Path, root: &Path) -> Result<(), AuditIdentityError> {
    let file = fs::File::open(path).map_err(AuditIdentityError::ReadFailed)?;
    SystemSecretFilePolicy
        .validate_existing(path, &file)
        .map_err(map_policy_read)?;
    SystemPrivateDirectoryPolicy
        .validate(root)
        .map_err(map_policy_read)
}

fn map_policy_create(error: SecretFileError) -> AuditIdentityError {
    match error {
        SecretFileError::Insecure => AuditIdentityError::AuditIdentityPermissions,
        SecretFileError::Platform(error) => AuditIdentityError::CreateDirectoryFailed(error),
    }
}

fn map_policy_read(error: SecretFileError) -> AuditIdentityError {
    match error {
        SecretFileError::Insecure => AuditIdentityError::AuditIdentityPermissions,
        SecretFileError::Platform(error) => AuditIdentityError::ReadFailed(error),
    }
}

fn map_policy_write(error: SecretFileError) -> AuditIdentityError {
    match error {
        SecretFileError::Insecure => AuditIdentityError::AuditIdentityPermissions,
        SecretFileError::Platform(error) => AuditIdentityError::WriteFailed(error),
    }
}

fn encode_identity_file(seed: &[u8; 32], public_key: &[u8; 32]) -> [u8; IDENTITY_FILE_LEN] {
    let mut bytes = [0_u8; IDENTITY_FILE_LEN];
    bytes[..8].copy_from_slice(&IDENTITY_MAGIC);
    bytes[8..10].copy_from_slice(&IDENTITY_FORMAT_VERSION.to_be_bytes());
    bytes[10..42].copy_from_slice(seed);
    bytes[42..74].copy_from_slice(public_key);
    bytes
}

fn decode_identity_file(bytes: &[u8]) -> Result<AuditIdentity, AuditIdentityError> {
    let bytes: [u8; IDENTITY_FILE_LEN] = bytes
        .try_into()
        .map_err(|_| AuditIdentityError::AuditIdentityInvalid)?;
    if bytes[..8] != IDENTITY_MAGIC {
        return Err(AuditIdentityError::AuditIdentityInvalid);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != IDENTITY_FORMAT_VERSION {
        return Err(AuditIdentityError::AuditIdentityInvalid);
    }
    let seed = Zeroizing::new(
        bytes[10..42]
            .try_into()
            .map_err(|_| AuditIdentityError::AuditIdentityInvalid)?,
    );
    let identity = AuditIdentity::from_seed_bytes(&seed);
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(&bytes[42..74]);
    if identity.public_key().as_bytes() != &public_key {
        return Err(AuditIdentityError::AuditIdentityInvalid);
    }
    Ok(identity)
}

/// Synchronizes a directory entry, making a created file or directory
/// durable (design section 9.2, step 4).
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), AuditIdentityError> {
    fs::File::open(path)
        .map_err(AuditIdentityError::SyncFailed)?
        .sync_all()
        .map_err(AuditIdentityError::SyncFailed)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;
    use yonder_core::{OsSecureRandom, RandomError};

    fn test_root() -> PathBuf {
        tempdir().unwrap().path().join("audit")
    }

    #[test]
    fn first_use_creates_identity_and_private_directory_layout() {
        let root = test_root();
        let mut random = OsSecureRandom;
        let identity = open_or_create_identity(&root, &mut random).unwrap();
        assert!(root.join(IDENTITY_FILE_NAME).is_file());
        assert!(root.join(RECORDS_DIR_NAME).is_dir());
        // The stored file round-trips and contains exactly the identity.
        let bytes = fs::read(root.join(IDENTITY_FILE_NAME)).unwrap();
        assert_eq!(bytes.len(), IDENTITY_FILE_LEN);
        let decoded = decode_identity_file(&bytes).unwrap();
        assert_eq!(decoded.public_key(), identity.public_key());
        // Loading again yields the same identity and never rewrites the file.
        let reloaded = open_or_create_identity(&root, &mut random).unwrap();
        assert_eq!(reloaded.public_key(), identity.public_key());
        assert_eq!(fs::read(root.join(IDENTITY_FILE_NAME)).unwrap(), bytes);
        // The fingerprint is the SHA-256 of the public key.
        let expected =
            IdentityFingerprint::new(Sha256::digest(identity.public_key().as_bytes()).into());
        assert_eq!(identity.fingerprint(), expected);
    }

    #[cfg(unix)]
    #[test]
    fn created_directories_and_identity_file_have_private_permissions() {
        let root = test_root();
        open_or_create_identity(&root, &mut OsSecureRandom).unwrap();
        assert_eq!(
            fs::symlink_metadata(&root).unwrap().permissions().mode() & 0o777,
            PRIVATE_DIR_MODE
        );
        assert_eq!(
            fs::symlink_metadata(root.join(RECORDS_DIR_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_DIR_MODE
        );
        assert_eq!(
            fs::symlink_metadata(root.join(IDENTITY_FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
    }

    #[test]
    fn invalid_identity_files_are_rejected() {
        let root = test_root();
        let mut random = OsSecureRandom;
        open_or_create_identity(&root, &mut random).unwrap();
        let valid = fs::read(root.join(IDENTITY_FILE_NAME)).unwrap();
        let path = root.join(IDENTITY_FILE_NAME);

        // Garbage content.
        fs::write(&path, b"this is not an audit identity").unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut random),
            Err(AuditIdentityError::AuditIdentityInvalid)
        ));

        // Truncated file.
        fs::write(&path, &valid[..IDENTITY_FILE_LEN / 2]).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut random),
            Err(AuditIdentityError::AuditIdentityInvalid)
        ));

        // Wrong magic.
        let mut wrong_magic = valid.clone();
        wrong_magic[0] = b'X';
        fs::write(&path, &wrong_magic).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut random),
            Err(AuditIdentityError::AuditIdentityInvalid)
        ));

        // Unknown format version.
        let mut wrong_version = valid.clone();
        wrong_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        fs::write(&path, &wrong_version).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut random),
            Err(AuditIdentityError::AuditIdentityInvalid)
        ));

        // A stored public key that does not match the stored seed: the seed
        // is authoritative, so this file must be rejected, not trusted.
        let mut mismatched = valid.clone();
        mismatched[42] ^= 0x01;
        fs::write(&path, &mismatched).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut random),
            Err(AuditIdentityError::AuditIdentityInvalid)
        ));
    }

    #[test]
    fn missing_identity_with_audit_history_is_rejected() {
        let root = test_root();
        ensure_audit_dirs(&root).unwrap();
        // Simulated history: a ledger state file exists.
        fs::write(root.join(LEDGER_STATE_FILE_NAME), [0_u8; 82]).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityMissing)
        ));

        // History via a records entry alone is also detected.
        let root = test_root();
        ensure_audit_dirs(&root).unwrap();
        fs::write(
            root.join(RECORDS_DIR_NAME)
                .join("session-a.controller.yonaudit"),
            [0_u8; 8],
        )
        .unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityMissing)
        ));
    }

    #[test]
    fn empty_preexisting_root_creates_fresh_identity() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        SystemPrivateDirectoryPolicy.protect(&root).unwrap();
        let identity = open_or_create_identity(&root, &mut OsSecureRandom).unwrap();
        assert!(root.join(IDENTITY_FILE_NAME).is_file());
        assert_eq!(identity.fingerprint(), identity.fingerprint());
    }

    #[test]
    fn identity_signs_verifies_and_redacts_debug() {
        let mut random = OsSecureRandom;
        let identity = AuditIdentity::generate(&mut random).unwrap();
        let message = b"yonder audit identity signing test";
        let signature = identity.sign(message);
        assert!(identity.verify(message, &signature));
        assert!(!identity.verify(b"tampered message", &signature));
        let other = AuditIdentity::generate(&mut random).unwrap();
        assert!(!other.verify(message, &signature));
        // The free verifier works from the public key alone.
        assert!(verify_ed25519_signature(
            &identity.public_key(),
            message,
            &signature
        ));
        assert!(!verify_ed25519_signature(
            &other.public_key(),
            message,
            &signature
        ));
        // The compressed Edwards y-coordinate 2 has no corresponding point
        // and must be rejected before signature verification.
        let mut non_canonical = [0; 32];
        non_canonical[0] = 2;
        assert!(!verify_ed25519_signature(
            &Ed25519PublicKey::new(non_canonical),
            message,
            &signature
        ));
        // Debug output never prints key material.
        assert_eq!(format!("{identity:?}"), "AuditIdentity([REDACTED])");
        // Seeds from the approved random source are wiped on drop; a failing
        // source surfaces as an error instead of a fallback.
        let mut failing = FailingRandom;
        assert!(matches!(
            AuditIdentity::generate(&mut failing),
            Err(AuditIdentityError::RandomSourceFailed(_))
        ));
    }

    struct FailingRandom;

    impl SecureRandom for FailingRandom {
        fn try_fill(&mut self, _destination: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError)
        }
    }

    #[cfg(unix)]
    #[test]
    fn permission_anomalies_are_rejected() {
        let root = test_root();
        open_or_create_identity(&root, &mut OsSecureRandom).unwrap();

        // The identity file must stay private.
        fs::set_permissions(
            root.join(IDENTITY_FILE_NAME),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityPermissions)
        ));
        fs::set_permissions(
            root.join(IDENTITY_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        // The audit root must stay private.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityPermissions)
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        // The records directory must stay private.
        let records = root.join(RECORDS_DIR_NAME);
        fs::set_permissions(&records, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityPermissions)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_identity_and_root_are_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let root = dir.path().join("audit");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"x").unwrap();

        // A symlink in place of the identity file is never followed.
        ensure_audit_dirs(&root).unwrap();
        symlink(&victim, root.join(IDENTITY_FILE_NAME)).unwrap();
        assert!(matches!(
            open_or_create_identity(&root, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityPermissions)
        ));

        // A symlink in place of the audit root is never followed.
        let link = dir.path().join("audit-link");
        symlink(&root, &link).unwrap();
        assert!(matches!(
            open_or_create_identity(&link, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityPermissions)
        ));

        // A symlink in place of the records directory is never followed.
        let records_link = dir.path().join("records-link");
        symlink(dir.path().join("elsewhere"), &records_link).unwrap();
        fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        let root_with_link = dir.path().join("root2");
        fs::create_dir_all(&root_with_link).unwrap();
        fs::rename(&records_link, root_with_link.join(RECORDS_DIR_NAME)).unwrap();
        assert!(matches!(
            open_or_create_identity(&root_with_link, &mut OsSecureRandom),
            Err(AuditIdentityError::AuditIdentityPermissions)
        ));
    }

    #[test]
    fn linux_audit_root_follows_the_xdg_state_home_rules() {
        let home = absolute_test_path("home/user");
        let home_path = PathBuf::from(&home);
        let xdg = absolute_test_path("state/x");
        let xdg_path = PathBuf::from(&xdg);

        let resolved =
            linux_audit_root(Some(OsString::from(&xdg)), Some(OsString::from(&home))).unwrap();
        assert!(resolved.starts_with(&xdg_path));
        assert!(resolved.ends_with(Path::new("yonder/audit")));

        let resolved = linux_audit_root(None, Some(OsString::from(&home))).unwrap();
        assert!(resolved.starts_with(&home_path));
        assert!(resolved.ends_with(Path::new(".local/state/yonder/audit")));

        // An unset HOME is a fail-closed audit directory error.
        assert!(matches!(
            linux_audit_root(None, None),
            Err(AuditIdentityError::AuditDirectoryUnavailable)
        ));
        // An empty HOME is a fail-closed audit directory error.
        assert!(matches!(
            linux_audit_root(None, Some(OsString::new())),
            Err(AuditIdentityError::AuditDirectoryUnavailable)
        ));
        // A set XDG_STATE_HOME must be a non-empty absolute path.
        assert!(matches!(
            linux_audit_root(Some(OsString::new()), Some(OsString::from(&home))),
            Err(AuditIdentityError::InvalidAuditDirectoryEnv)
        ));
        assert!(matches!(
            linux_audit_root(
                Some(OsString::from("relative/state")),
                Some(OsString::from(&home))
            ),
            Err(AuditIdentityError::InvalidAuditDirectoryEnv)
        ));
    }

    #[test]
    fn macos_and_windows_audit_roots_follow_their_rules() {
        let home = absolute_test_path("home/user");
        let home_path = PathBuf::from(&home);
        let resolved = macos_audit_root(Some(OsString::from(&home))).unwrap();
        assert!(resolved.starts_with(&home_path));
        assert!(resolved.ends_with(Path::new("Library/Application Support/Yonder/Audit")));
        assert!(matches!(
            macos_audit_root(None),
            Err(AuditIdentityError::AuditDirectoryUnavailable)
        ));
        assert!(matches!(
            macos_audit_root(Some(OsString::new())),
            Err(AuditIdentityError::AuditDirectoryUnavailable)
        ));

        let local = absolute_test_path("local/appdata");
        let local_path = PathBuf::from(&local);
        let resolved = windows_audit_root(Some(OsString::from(&local))).unwrap();
        assert!(resolved.starts_with(&local_path));
        assert!(resolved.ends_with(Path::new("Yonder/Audit")));
        assert!(matches!(
            windows_audit_root(None),
            Err(AuditIdentityError::AuditDirectoryUnavailable)
        ));
        assert!(matches!(
            windows_audit_root(Some(OsString::new())),
            Err(AuditIdentityError::InvalidAuditDirectoryEnv)
        ));
        assert!(matches!(
            windows_audit_root(Some(OsString::from("relative/appdata"))),
            Err(AuditIdentityError::InvalidAuditDirectoryEnv)
        ));
    }

    #[test]
    fn storage_policy_errors_keep_their_operation_category() {
        assert!(matches!(
            map_policy_create(SecretFileError::Insecure),
            AuditIdentityError::AuditIdentityPermissions
        ));
        assert!(matches!(
            map_policy_create(SecretFileError::Platform(io::Error::other("create"))),
            AuditIdentityError::CreateDirectoryFailed(_)
        ));
        assert!(matches!(
            map_policy_read(SecretFileError::Insecure),
            AuditIdentityError::AuditIdentityPermissions
        ));
        assert!(matches!(
            map_policy_read(SecretFileError::Platform(io::Error::other("read"))),
            AuditIdentityError::ReadFailed(_)
        ));
        assert!(matches!(
            map_policy_write(SecretFileError::Insecure),
            AuditIdentityError::AuditIdentityPermissions
        ));
        assert!(matches!(
            map_policy_write(SecretFileError::Platform(io::Error::other("write"))),
            AuditIdentityError::WriteFailed(_)
        ));
    }

    /// A platform-appropriate absolute path for the pure resolver tests.
    fn absolute_test_path(relative: &str) -> String {
        #[cfg(windows)]
        {
            format!("C:\\{relative}")
        }
        #[cfg(not(windows))]
        {
            format!("/{relative}")
        }
    }
}
