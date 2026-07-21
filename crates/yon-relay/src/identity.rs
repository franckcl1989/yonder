use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use thiserror::Error;
use yonder_core::SecretDocument;
use yonder_net::Keypair;
use yonder_net::identity::{decode_identity, encode_identity};

use crate::{SecretFileError, SecretFilePolicy, SystemSecretFilePolicy};

const MAX_IDENTITY_DOCUMENT: u64 = 1_024;

/// Persistent relay identity storage behind a replaceable cold-path boundary.
pub trait IdentityStore {
    fn create(&self, path: &Path, identity: &Keypair) -> Result<(), IdentityError>;
    fn read(&self, path: &Path) -> Result<Keypair, IdentityError>;
}

/// Cross-platform atomic filesystem identity storage.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileIdentityStore;

/// Identity persistence and decoding failures.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("the relay identity already exists")]
    AlreadyExists,
    #[error("the relay identity document is too large")]
    TooLarge,
    #[error("the relay identity document is invalid")]
    Invalid,
    #[error("the relay identity file or parent directory permits untrusted access")]
    InsecurePermissions,
    #[error("relay identity filesystem I/O failed")]
    Io(#[source] std::io::Error),
}

impl IdentityStore for FileIdentityStore {
    fn create(&self, path: &Path, identity: &Keypair) -> Result<(), IdentityError> {
        self.create_with(path, identity, &SystemSecretFilePolicy)
    }

    fn read(&self, path: &Path) -> Result<Keypair, IdentityError> {
        self.read_with(path, &SystemSecretFilePolicy)
    }
}

impl FileIdentityStore {
    fn create_with(
        self,
        path: &Path,
        identity: &Keypair,
        policy: &impl SecretFilePolicy,
    ) -> Result<(), IdentityError> {
        let parent = parent_directory(path)?;
        let document = encode_identity(identity).map_err(|_| IdentityError::Invalid)?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(IdentityError::Io)?;
        policy
            .protect_new(temporary.path(), temporary.as_file())
            .map_err(map_policy_error)?;
        temporary
            .write_all(document.as_bytes())
            .map_err(IdentityError::Io)?;
        temporary.as_file().sync_all().map_err(IdentityError::Io)?;
        temporary
            .persist_noclobber(path)
            .map_err(|error| persist_error(error.error))?;
        sync_parent(parent)?;
        Ok(())
    }

    fn read_with(
        self,
        path: &Path,
        policy: &impl SecretFilePolicy,
    ) -> Result<Keypair, IdentityError> {
        let file = File::open(path).map_err(IdentityError::Io)?;
        policy
            .validate_existing(path, &file)
            .map_err(map_policy_error)?;
        let metadata = file.metadata().map_err(IdentityError::Io)?;
        if metadata.len() > MAX_IDENTITY_DOCUMENT {
            return Err(IdentityError::TooLarge);
        }
        let document = read_document(file, metadata.len())?;
        decode_identity(document.as_bytes()).map_err(|_| IdentityError::Invalid)
    }
}

fn map_policy_error(error: SecretFileError) -> IdentityError {
    match error {
        SecretFileError::Insecure => IdentityError::InsecurePermissions,
        SecretFileError::Platform(error) => IdentityError::Io(error),
    }
}

fn persist_error(error: std::io::Error) -> IdentityError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        IdentityError::AlreadyExists
    } else {
        IdentityError::Io(error)
    }
}

fn read_document(reader: impl Read, reported_len: u64) -> Result<SecretDocument, IdentityError> {
    if reported_len > MAX_IDENTITY_DOCUMENT {
        return Err(IdentityError::TooLarge);
    }
    let mut document = Vec::with_capacity(reported_len as usize);
    let read = reader
        .take(MAX_IDENTITY_DOCUMENT + 1)
        .read_to_end(&mut document);
    let document = SecretDocument::new(document);
    read.map_err(IdentityError::Io)?;
    if document.as_bytes().len() as u64 > MAX_IDENTITY_DOCUMENT {
        return Err(IdentityError::TooLarge);
    }
    Ok(document)
}

fn parent_directory(path: &Path) -> Result<&Path, IdentityError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        Some(_) | None => Ok(Path::new(".")),
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), IdentityError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(IdentityError::Io)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), IdentityError> {
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        FileIdentityStore, IdentityError, IdentityStore, map_policy_error, parent_directory,
        persist_error, read_document,
    };
    use std::fs;
    #[cfg(not(unix))]
    use std::fs::File;
    use std::io::{self, Cursor, Read};
    use std::path::Path;
    use tempfile::{TempDir, tempdir};
    use yonder_net::Keypair;

    #[cfg(not(unix))]
    use crate::SecretFilePolicy as _;

    #[cfg(unix)]
    fn make_owner_only(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn make_owner_only(path: &Path) {
        let file = File::open(path).unwrap();
        crate::SystemSecretFilePolicy
            .protect_new(path, &file)
            .unwrap();
    }

    fn test_directory() -> TempDir {
        let directory = tempdir().unwrap();
        secure_test_directory(directory.path());
        directory
    }

    #[cfg(not(windows))]
    fn secure_test_directory(_path: &Path) {}

    #[cfg(windows)]
    fn secure_test_directory(path: &Path) {
        use std::process::{Command, Stdio};

        const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$path=$env:YONDER_TEST_DIRECTORY
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$administrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true,$false)
$rights=[Security.AccessControl.FileSystemRights]::FullControl
$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagate=[Security.AccessControl.PropagationFlags]::None
$allow=[Security.AccessControl.AccessControlType]::Allow
foreach($sid in @($current,$system,$administrators)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$propagate,$allow);[void]$acl.AddAccessRule($rule)}
[IO.Directory]::SetAccessControl($path,$acl)
exit 0
"#;
        let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let status = Command::new(executable)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                SCRIPT,
            ])
            .env("YONDER_TEST_DIRECTORY", path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn identity_is_atomic_round_trips_and_refuses_overwrite() {
        let directory = test_directory();
        let path = directory.path().join("relay.identity");
        let identity = Keypair::generate_ed25519();
        let peer = identity.public().to_peer_id();
        let store = FileIdentityStore;
        store.create(&path, &identity).unwrap();
        assert_eq!(store.read(&path).unwrap().public().to_peer_id(), peer);
        assert!(matches!(
            store.create(&path, &Keypair::generate_ed25519()),
            Err(IdentityError::AlreadyExists)
        ));
    }

    #[test]
    fn insecure_permission_error_is_platform_neutral_and_actionable() {
        assert_eq!(
            IdentityError::InsecurePermissions.to_string(),
            "the relay identity file or parent directory permits untrusted access"
        );
        assert!(matches!(
            map_policy_error(crate::SecretFileError::Insecure),
            IdentityError::InsecurePermissions
        ));
        assert!(matches!(
            map_policy_error(crate::SecretFileError::Platform(io::Error::other(
                "platform"
            ))),
            IdentityError::Io(error) if error.kind() == io::ErrorKind::Other
        ));
    }

    #[test]
    fn invalid_and_oversized_documents_are_rejected() {
        let directory = test_directory();
        let invalid = directory.path().join("invalid.identity");
        fs::write(&invalid, [1, 2, 3]).unwrap();
        make_owner_only(&invalid);
        assert!(matches!(
            FileIdentityStore.read(&invalid),
            Err(IdentityError::Invalid)
        ));

        let oversized = directory.path().join("large.identity");
        fs::write(&oversized, vec![0; 1_025]).unwrap();
        make_owner_only(&oversized);
        assert!(matches!(
            FileIdentityStore.read(&oversized),
            Err(IdentityError::TooLarge)
        ));

        assert!(matches!(
            FileIdentityStore.read(&directory.path().join("missing.identity")),
            Err(IdentityError::Io(_))
        ));
        assert!(matches!(
            FileIdentityStore.create(
                &directory.path().join("missing").join("relay.identity"),
                &Keypair::generate_ed25519()
            ),
            Err(IdentityError::Io(_))
        ));
        assert_eq!(
            IdentityError::Invalid.to_string(),
            "the relay identity document is invalid"
        );
    }

    #[cfg(unix)]
    #[test]
    fn identity_read_rejects_group_or_other_access() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = test_directory();
        let path = directory.path().join("relay.identity");
        FileIdentityStore
            .create(&path, &Keypair::generate_ed25519())
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            FileIdentityStore.read(&path),
            Err(IdentityError::InsecurePermissions)
        ));
    }

    #[test]
    fn parentless_identity_paths_use_the_current_directory() {
        assert_eq!(
            parent_directory(Path::new("relay.identity")).unwrap(),
            Path::new(".")
        );
    }

    #[test]
    fn persistence_and_racing_size_errors_remain_structured() {
        assert!(matches!(
            persist_error(io::Error::new(io::ErrorKind::AlreadyExists, "exists")),
            IdentityError::AlreadyExists
        ));
        assert!(matches!(
            persist_error(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
            IdentityError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied
        ));

        assert!(matches!(
            read_document(Cursor::new(vec![0_u8; 1_025]), 1_024),
            Err(IdentityError::TooLarge)
        ));
        assert_eq!(
            read_document(Cursor::new(vec![0_u8; 1_024]), 1_024)
                .unwrap()
                .as_bytes()
                .len(),
            1_024
        );
        assert!(matches!(
            read_document(Cursor::new(Vec::new()), 1_025),
            Err(IdentityError::TooLarge)
        ));
        assert!(matches!(
            read_document(FailingReader, 0),
            Err(IdentityError::Io(error)) if error.kind() == io::ErrorKind::Other
        ));
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failed"))
        }
    }
}
