use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use thiserror::Error;
use yonder_core::SecretDocument;
use yonder_net::Keypair;
use yonder_net::identity::{decode_identity, encode_identity};

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
    #[error("relay identity filesystem I/O failed")]
    Io(#[source] std::io::Error),
}

impl IdentityStore for FileIdentityStore {
    fn create(&self, path: &Path, identity: &Keypair) -> Result<(), IdentityError> {
        let parent = parent_directory(path)?;
        let document = encode_identity(identity).map_err(|_| IdentityError::Invalid)?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(IdentityError::Io)?;
        set_owner_only_permissions(temporary.as_file()).map_err(IdentityError::Io)?;
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

    fn read(&self, path: &Path) -> Result<Keypair, IdentityError> {
        let file = File::open(path).map_err(IdentityError::Io)?;
        let metadata = file.metadata().map_err(IdentityError::Io)?;
        if metadata.len() > MAX_IDENTITY_DOCUMENT {
            return Err(IdentityError::TooLarge);
        }
        let document = read_document(file, metadata.len())?;
        decode_identity(document.as_bytes()).map_err(|_| IdentityError::Invalid)
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
fn set_owner_only_permissions(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_file: &File) -> std::io::Result<()> {
    Ok(())
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
        FileIdentityStore, IdentityError, IdentityStore, parent_directory, persist_error,
        read_document,
    };
    use std::fs;
    use std::io::{self, Cursor, Read};
    use std::path::Path;
    use tempfile::tempdir;
    use yonder_net::Keypair;

    #[test]
    fn identity_is_atomic_round_trips_and_refuses_overwrite() {
        let directory = tempdir().unwrap();
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
    fn invalid_and_oversized_documents_are_rejected() {
        let directory = tempdir().unwrap();
        let invalid = directory.path().join("invalid.identity");
        fs::write(&invalid, [1, 2, 3]).unwrap();
        assert!(matches!(
            FileIdentityStore.read(&invalid),
            Err(IdentityError::Invalid)
        ));

        let oversized = directory.path().join("large.identity");
        fs::write(&oversized, vec![0; 1_025]).unwrap();
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
