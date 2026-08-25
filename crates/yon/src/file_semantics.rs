//! Native file-transfer file semantics for the 0.2.0 controller and host
//! (design sections 8.2, 8.3, 8.4, 8.5, 13, 14 and 15.1).
//!
//! The module implements the file-system side of a single file transfer in
//! isolation from the wire and session layers:
//!
//! - **Base directory.** Each endpoint captures its absolute working
//!   directory once per session ([`BaseDirectory::capture`]). Every relative
//!   protocol path is resolved against that directory; absolute paths are
//!   interpreted by the local platform unchanged. Remote and local paths are
//!   never interpreted by the other side (section 8.5).
//! - **Sources.** [`SourceFile::open`] opens the path first and judges the
//!   object type and size exclusively from the opened handle (section 8.2).
//!   Only regular files are accepted; directories, pipes, sockets, devices,
//!   Windows device objects and other special files are rejected with
//!   [`FileSemanticsError::SourceNotRegularFile`]. Reading is streaming with
//!   at most [`CHUNK_SIZE`] bytes per call, never beyond the size recorded at
//!   open, and a re-check of the same handle detects growth or shrinkage
//!   before `Finish` is sent (section 14).
//! - **Destinations.** [`resolve_destination`] computes the final absolute
//!   path and the directory that will hold the private temporary file. The
//!   final path must not exist at resolution time and is never overwritten:
//!   an existing target, an existing directory target without a valid
//!   peer-provided base file name, a missing parent or a parent that is not a
//!   directory all fail with the corresponding structured error. Parent
//!   directories are never created automatically (sections 8.3, 8.4).
//! - **Private temporary files and commit.** [`PrivateTempFile::create`]
//!   delegates unpredictable exclusive creation next to the final path to
//!   [`tempfile::NamedTempFile`].
//!   Bytes are written with a streamed SHA-256 running in lock-step; on
//!   [`PrivateTempFile::finish`] the file is flushed and synchronised, and
//!   [`SealedTempFile::verify_finish`] enforces the declared size and digest.
//!   The final no-replace operation is owned by
//!   [`tempfile::NamedTempFile::persist_noclobber`], so an existing final
//!   object fails and is never replaced, truncated or deleted first. The
//!   temporary file is removed on every failure path by the crate's guard.
//! - **Change detection boundary.** In-place modification that preserves both
//!   the size and the modification identity cannot be detected on every
//!   platform (for example file systems with coarse time stamps); the design
//!   explicitly accepts this boundary (section 14). The receiver still
//!   verifies that the bytes it wrote match the digest the sender computed,
//!   so a delivered file always matches what the sender actually sent.
//!
//! # Paths, names and logging
//!
//! Protocol paths are UTF-8, at most [`MAX_PATH_LEN`] bytes, without NUL,
//! C0/C1 control characters or DEL; the wire validators
//! `validate_protocol_path` and `validate_default_file_name` are reapplied at
//! this boundary. On Windows the additional receiving-platform rules apply:
//! peer base file names must resolve to exactly one ordinary name component
//! (no drive-relative or prefix forms) and must not be reserved device names,
//! and drive-relative destination paths are rejected because they cannot be
//! resolved against the base directory.
//!
//! Error messages and `Debug` output never contain full paths, file names or
//! temporary file names: [`FileSemanticsError`] carries only the error
//! category, error codes and sizes, and the path-holding types implement a
//! redacted `Debug`. Callers must apply the same rule to their own logs and
//! must never log [`PrivateTempFile::path`].
//!
//! # Memory bounds
//!
//! All reading, writing and digest computation is streaming over a fixed
//! 64 KiB buffer ([`CHUNK_SIZE`]); nothing is ever allocated proportional to
//! the file size (section 15.1). File sizes are `u64` with no product-level
//! cap; actual limits come from the platform and file systems (section 15.5).

use std::fs;
use std::future::Future;
use std::io::{self, Read, Write};
#[cfg(windows)]
use std::path::Prefix;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempPath};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yonder_core::wire::file_transfer::{
    FileTransferErrorCode, MAX_PATH_LEN, Sha256Digest, validate_default_file_name,
    validate_protocol_path,
};

/// The fixed streaming buffer size in bytes: file I/O, wire blocks and digest
/// computation all work in chunks of at most this size (design 15.1).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// The absolute working directory captured once per session.
///
/// The controller captures it when `yon connect` starts, the host when the
/// session shell starts; it never changes during the session. All relative
/// protocol paths resolve against it; absolute paths are kept verbatim and
/// interpreted by the local platform.
#[derive(Clone, PartialEq, Eq)]
pub struct BaseDirectory(PathBuf);

impl BaseDirectory {
    /// Captures the process working directory as the session base directory.
    ///
    /// Fails with [`FileSemanticsError::BaseDirectoryUnavailable`] when the
    /// working directory cannot be obtained (for example because it was
    /// deleted). The base directory is always absolute.
    pub fn capture() -> Result<Self, FileSemanticsError> {
        let path = std::env::current_dir().map_err(FileSemanticsError::BaseDirectoryUnavailable)?;
        Ok(Self(path))
    }

    #[cfg(test)]
    pub(crate) fn from_absolute_path_for_test(path: &Path) -> Self {
        assert!(path.is_absolute(), "a test base directory must be absolute");
        Self(path.to_path_buf())
    }

    /// Borrows the captured directory path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Validates `path` as a protocol path and resolves it against the base
    /// directory: relative paths are joined to the base directory, absolute
    /// paths are returned verbatim.
    ///
    /// Empty strings are not valid here (an empty path only means "the
    /// default destination" in the target field) and fail with
    /// [`FileSemanticsError::InvalidRequest`].
    pub fn resolve(&self, path: &str) -> Result<PathBuf, FileSemanticsError> {
        if path.is_empty() {
            return Err(FileSemanticsError::InvalidRequest);
        }
        validate_protocol_path_string(path)?;
        #[cfg(windows)]
        {
            // A drive-relative path (for example "C:foo") resolves against
            // the working directory of that drive, not against the base
            // directory; joining it would escape the base, so it is
            // rejected instead of being reinterpreted.
            if is_drive_relative(path) {
                return Err(FileSemanticsError::InvalidRequest);
            }
        }
        Ok(self.resolve_validated(path))
    }

    fn resolve_validated(&self, path: &str) -> PathBuf {
        let candidate = Path::new(path);
        if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            self.0.join(candidate)
        }
    }

    #[cfg(test)]
    fn from_path_buf(path: PathBuf) -> Self {
        Self(path)
    }
}

impl std::fmt::Debug for BaseDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BaseDirectory([REDACTED])")
    }
}

/// The identity of an opened source file at one moment: its size plus the
/// platform's modification identity (usually the last-modification time).
///
/// A modification identity of `None` means the platform provided none; the
/// identity then consists of the size alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceIdentity {
    size: u64,
    modified: Option<SystemTime>,
}

impl SourceIdentity {
    /// The file size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The modification identity, when the platform provides one.
    #[must_use]
    pub fn modified(&self) -> Option<SystemTime> {
        self.modified
    }

    /// True when `self` differs from `initial` in size or modification
    /// identity (a `None` versus `Some` difference counts as a change).
    ///
    /// This is the change test of design section 14. An in-place
    /// modification that preserves both size and modification identity
    /// cannot be detected on every platform and is an accepted boundary; the
    /// transferred content is still protected by the sender/receiver digest
    /// agreement.
    #[must_use]
    pub fn changed_since(&self, initial: &SourceIdentity) -> bool {
        self.size != initial.size || self.modified != initial.modified
    }
}

/// An opened, regular source file, judged exclusively through its handle.
///
/// The initial size and modification identity are recorded from the opened
/// handle; [`SourceFile::read_chunked`] never returns bytes beyond that
/// initial size, and [`SourceFile::recheck`] re-reads the identity from the
/// same handle to detect changes before `Finish` is sent (design sections
/// 8.2 and 14).
#[derive(Debug)]
pub struct SourceFile {
    file: fs::File,
    initial_size: u64,
    initial_modified: Option<SystemTime>,
    read: u64,
}

impl SourceFile {
    /// Opens `path` and records the initial size and modification identity
    /// from the opened handle.
    ///
    /// The final object must be a regular file: empty files, regular files
    /// and paths that resolve through symbolic links to a regular file are
    /// accepted; directories, pipes, sockets, character devices, block
    /// devices, Windows device objects and other special files are rejected
    /// with [`FileSemanticsError::SourceNotRegularFile`]. On Unix a
    /// path-level probe runs before the open for one reason only: opening a
    /// FIFO without `O_NONBLOCK` blocks forever and safe `std` offers no
    /// non-blocking open flag. The probe never judges the transfer object;
    /// type and size are still taken exclusively from the opened handle
    /// (design 8.2). On Windows, device and verbatim namespaces and paths
    /// whose last component is a reserved device name (for example `NUL`,
    /// `CON`, `COM1`) are rejected before any system call. Ordinary UNC
    /// paths remain valid file paths and are judged through the opened
    /// handle like local paths.
    pub fn open(path: &Path) -> Result<Self, FileSemanticsError> {
        #[cfg(unix)]
        {
            let probe = fs::metadata(path).map_err(map_source_probe_error)?;
            if !probe.is_file() {
                return Err(FileSemanticsError::SourceNotRegularFile);
            }
        }
        #[cfg(windows)]
        reject_windows_special_sources(path)?;
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) => {
                #[cfg(windows)]
                {
                    // Windows refuses to open a directory; classify the
                    // refusal from the path only as an error-classification
                    // aid. The handle remains authoritative after an open.
                    if error.kind() == io::ErrorKind::PermissionDenied
                        && fs::metadata(path).is_ok_and(|meta| meta.is_dir())
                    {
                        return Err(FileSemanticsError::SourceNotRegularFile);
                    }
                }
                return Err(map_source_open_error(error));
            }
        };
        let metadata = file.metadata().map_err(map_handle_metadata_error)?;
        if !metadata.is_file() {
            return Err(FileSemanticsError::SourceNotRegularFile);
        }
        Ok(Self {
            file,
            initial_size: metadata.len(),
            initial_modified: metadata.modified().ok(),
            read: 0,
        })
    }

    /// The initial size recorded at open time. Only this many bytes are ever
    /// read, even if the file grows while it is transferred.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.initial_size
    }

    /// The initial modification identity recorded at open time.
    #[must_use]
    pub fn modified_identity(&self) -> Option<SystemTime> {
        self.initial_modified
    }

    /// The full initial identity recorded at open time.
    #[must_use]
    pub fn initial_identity(&self) -> SourceIdentity {
        SourceIdentity {
            size: self.initial_size,
            modified: self.initial_modified,
        }
    }

    /// The identity re-read live from the same open handle.
    pub fn current_identity(&self) -> Result<SourceIdentity, FileSemanticsError> {
        let metadata = self.file.metadata().map_err(map_handle_metadata_error)?;
        Ok(SourceIdentity {
            size: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    /// Re-checks the same open handle against the identity recorded at open
    /// time and fails with [`FileSemanticsError::SourceChanged`] when the
    /// size or the modification identity changed.
    ///
    /// The transfer layer calls this after the last read and before sending
    /// `Finish` (design section 14). In-place modification preserving both
    /// size and modification identity is the accepted, documented boundary.
    pub fn recheck(&self) -> Result<(), FileSemanticsError> {
        if self
            .current_identity()?
            .changed_since(&self.initial_identity())
        {
            return Err(FileSemanticsError::SourceChanged);
        }
        Ok(())
    }

    /// The number of bytes handed out by [`SourceFile::read_chunked`] so far.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    /// Reads the next chunk of at most `min(buffer.len(), CHUNK_SIZE)` bytes,
    /// never beyond the initial size.
    ///
    /// Returns `Ok(0)` once the initial size has been fully read. Reaching
    /// end-of-file before the initial size means the file shrank; the open
    /// handle is re-checked and the failure is reported as
    /// [`FileSemanticsError::SourceChanged`] when the change is detectable,
    /// or [`FileSemanticsError::SizeMismatch`] otherwise.
    pub fn read_chunked(&mut self, buffer: &mut [u8]) -> Result<usize, FileSemanticsError> {
        let remaining = self.initial_size - self.read;
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len())
            .min(CHUNK_SIZE);
        if want == 0 {
            return Ok(0);
        }
        let n = loop {
            match self.file.read(&mut buffer[..want]) {
                Ok(0) => break 0,
                Ok(n) => break n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(map_read_error(error)),
            }
        };
        if n == 0 {
            self.recheck()?;
            return Err(FileSemanticsError::SizeMismatch {
                declared: self.initial_size,
                received: self.read,
            });
        }
        self.read += n as u64;
        Ok(n)
    }
}

/// The resolved destination of an upload or download.
///
/// Invariants guaranteed by [`resolve_destination`]:
///
/// - [`DestinationPlan::final_path`] is absolute;
/// - [`DestinationPlan::temp_dir`] is the directory of the final path and
///   exists;
/// - the final path did not exist at resolution time (checked with
///   `symlink_metadata`, which sees dangling symbolic links and reparse
///   points too), and the no-replace commit keeps it that way: a final
///   object created concurrently is never overwritten.
#[derive(Clone, PartialEq, Eq)]
pub struct DestinationPlan {
    final_path: PathBuf,
    temp_dir: PathBuf,
}

impl DestinationPlan {
    /// The final absolute target path. The temporary file lives in its
    /// directory and is committed here.
    #[must_use]
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// The directory of the final path; the private temporary file must be
    /// created here so the no-replace commit stays on one file system.
    #[must_use]
    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }
}

impl std::fmt::Debug for DestinationPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DestinationPlan")
            .finish_non_exhaustive()
    }
}

/// Resolves the final destination of a transfer against the session base
/// directory (design sections 8.3 and 8.4).
///
/// - An empty or absent `explicit_target` selects the default destination:
///   the base directory joined with the validated `default_name`.
/// - A non-empty `explicit_target` is validated as a protocol path and
///   resolved against the base directory (relative paths) or kept verbatim
///   (absolute paths). If the resolved path is an existing directory, the
///   validated `default_name` is joined into it; otherwise it is treated as
///   the complete final file path.
/// - The final path must not exist (any object: regular file, directory,
///   symbolic link, reparse point), its parent must exist and be a
///   directory, and parents are never created automatically.
///
/// The peer-provided `default_name` is validated with the receiving
/// platform's rules (design 8.4): it must be a single ordinary name
/// component, and on Windows it must not be a reserved device name, a
/// drive-relative form or contain a colon. Any violation fails with
/// [`FileSemanticsError::InvalidFileName`]; a peer name is never reinterpreted
/// as a path.
pub fn resolve_destination(
    base: &BaseDirectory,
    explicit_target: Option<&str>,
    default_name: Option<&str>,
) -> Result<DestinationPlan, FileSemanticsError> {
    let explicit = explicit_target.unwrap_or("");
    if explicit.is_empty() {
        let name = default_name.ok_or(FileSemanticsError::InvalidFileName)?;
        validate_default_file_name_on_receiving_platform(name)?;
        return build_plan(base.as_path().join(Path::new(name)));
    }
    validate_protocol_path_string(explicit)?;
    let resolved = base.resolve_validated(explicit);
    match fs::metadata(&resolved) {
        Ok(meta) if meta.is_dir() => {
            let name = default_name.ok_or(FileSemanticsError::InvalidFileName)?;
            validate_default_file_name_on_receiving_platform(name)?;
            build_plan(resolved.join(Path::new(name)))
        }
        Ok(_) => Err(FileSemanticsError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => build_plan(resolved),
        Err(error) => Err(map_probe_error(error)),
    }
}

/// Assembles the plan for an absolute final path: checks that nothing exists
/// there (including dangling links, seen via `symlink_metadata`) and that
/// the parent exists and is a directory.
fn build_plan(final_path: PathBuf) -> Result<DestinationPlan, FileSemanticsError> {
    ensure_destination_free(&final_path)?;
    let temp_dir = final_path
        .parent()
        .ok_or(FileSemanticsError::DestinationParentNotFound)?
        .to_path_buf();
    Ok(DestinationPlan {
        final_path,
        temp_dir,
    })
}

/// Enforces the "final target must not exist and its parent must be an
/// existing directory" invariants.
fn ensure_destination_free(final_path: &Path) -> Result<(), FileSemanticsError> {
    match fs::symlink_metadata(final_path) {
        Ok(_) => Err(FileSemanticsError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = final_path
                .parent()
                .ok_or(FileSemanticsError::DestinationParentNotFound)?;
            match fs::metadata(parent) {
                Ok(meta) if meta.is_dir() => Ok(()),
                Ok(_) => Err(FileSemanticsError::DestinationNotDirectory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Err(FileSemanticsError::DestinationParentNotFound)
                }
                Err(error) => Err(map_probe_error(error)),
            }
        }
        Err(error) => Err(map_probe_error(error)),
    }
}

/// A private temporary file created next to the final destination.
///
/// The name is generated by [`tempfile`] from operating-system randomness and
/// the file is created atomically without following an existing name. Bytes
/// are written with a streamed SHA-256 running in lock-step. The file is
/// removed on `Drop`, covering failures, cancellation and process exit as far
/// as best-effort cleanup can (design section 13).
pub struct PrivateTempFile {
    file: NamedTempFile,
    written: u64,
    hasher: Sha256,
}

impl std::fmt::Debug for PrivateTempFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The derived Debug would print the underlying `File`, whose Unix
        // representation includes the temporary path; the design forbids
        // logging temporary file names (section 18.4).
        formatter
            .debug_struct("PrivateTempFile")
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl PrivateTempFile {
    /// Creates a private temporary file in `directory` through `tempfile`.
    /// `directory` must exist (typically [`DestinationPlan::temp_dir`]).
    ///
    /// Creation failures are classified: a missing directory is
    /// [`FileSemanticsError::DestinationParentNotFound`], denied permission
    /// or a read-only file system is [`FileSemanticsError::PermissionDenied`],
    /// a full file system is [`FileSemanticsError::NoSpace`], and everything
    /// else is [`FileSemanticsError::TempFileCreateFailed`].
    pub fn create(directory: &Path) -> Result<Self, FileSemanticsError> {
        let file = NamedTempFile::new_in(directory).map_err(map_temp_create_error)?;
        Ok(Self {
            file,
            written: 0,
            hasher: Sha256::new(),
        })
    }

    /// The temporary file's path. It must never be logged.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// The number of bytes written so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Streams one block into the temporary file, updating the running byte
    /// count and SHA-256. Blocks are typically at most [`CHUNK_SIZE`] bytes.
    pub fn write_block(&mut self, bytes: &[u8]) -> Result<(), FileSemanticsError> {
        self.file
            .as_file_mut()
            .write_all(bytes)
            .map_err(map_write_error)?;
        self.written += bytes.len() as u64;
        self.hasher.update(bytes);
        Ok(())
    }

    /// Flushes the file at the application and runtime level (flush plus
    /// synchronisation, handing the written data to the operating system,
    /// design section 13.6) and seals it against further writes.
    ///
    /// The returned [`SealedTempFile`] owns the flushed handle together with
    /// the final byte count and digest.
    pub fn finish(mut self) -> Result<SealedTempFile, FileSemanticsError> {
        self.file.as_file_mut().flush().map_err(map_write_error)?;
        self.file.as_file().sync_all().map_err(map_write_error)?;
        let digest = Sha256Digest::new(self.hasher.finalize().into());
        Ok(SealedTempFile {
            file: self.file,
            written: self.written,
            digest,
        })
    }
}

/// A finished, flushed private temporary file that can no longer be written.
///
/// Created by [`PrivateTempFile::finish`]; the two-type split makes it
/// impossible to write after the digest was sealed. The temporary file is
/// removed on `Drop` if it still exists.
pub struct SealedTempFile {
    file: NamedTempFile,
    written: u64,
    digest: Sha256Digest,
}

impl SealedTempFile {
    /// The total number of bytes written to the temporary file.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The SHA-256 of exactly the written bytes.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// The temporary file's path. It must never be logged.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// Verifies the `Finish` payload against the sealed write: the written
    /// byte count must equal the declared size and the computed digest must
    /// equal the declared digest. Failures are
    /// [`FileSemanticsError::SizeMismatch`] and
    /// [`FileSemanticsError::DigestMismatch`]; nothing is committed.
    pub fn verify_finish(
        &self,
        declared_size: u64,
        declared_digest: Sha256Digest,
    ) -> Result<(), FileSemanticsError> {
        if self.written != declared_size {
            return Err(FileSemanticsError::SizeMismatch {
                declared: declared_size,
                received: self.written,
            });
        }
        if self.digest != declared_digest {
            return Err(FileSemanticsError::DigestMismatch);
        }
        Ok(())
    }

    /// Commits the temporary file to `final_path` with a no-replace commit:
    /// an existing final object fails with
    /// [`FileSemanticsError::DestinationExists`] and is never overwritten,
    /// truncated or deleted first. The temporary file must live in the same
    /// directory as `final_path` (as guaranteed by
    /// [`DestinationPlan::temp_dir`]); committing into another directory is
    /// rejected with [`FileSemanticsError::CommitFailed`].
    ///
    /// On success the final path contains the complete, verified file and
    /// the temporary name is removed; on failure the temporary file is
    /// removed best-effort by `Drop`. A file system that cannot perform the
    /// no-replace commit (for example one without hard links) fails with
    /// [`FileSemanticsError::CommitFailed`], as the design requires.
    pub fn commit(self, final_path: &Path) -> Result<(), FileSemanticsError> {
        let temp_path = self.file.path();
        if temp_path.parent() != final_path.parent() {
            return Err(FileSemanticsError::CommitFailed(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the destination is not in the temporary file's directory",
            )));
        }
        if let Err(error) = self.file.persist_noclobber(final_path) {
            return Err(match error.error.kind() {
                io::ErrorKind::AlreadyExists => FileSemanticsError::DestinationExists,
                io::ErrorKind::InvalidFilename => FileSemanticsError::InvalidFileName,
                _ => FileSemanticsError::CommitFailed(error.error),
            });
        }
        Ok(())
    }
}

impl std::fmt::Debug for SealedTempFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedTempFile")
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

/// A source used by the transfer orchestrator.
///
/// The returned futures are statically dispatched. The trait is deliberately
/// limited to the invariants the wire pump needs, so a different mature async
/// file implementation can replace Tokio without leaking its handle type.
pub trait TransferSource {
    /// The source size captured when its handle was opened.
    fn size(&self) -> u64;

    /// The number of source bytes returned so far.
    fn bytes_read(&self) -> u64;

    /// Reads one bounded source block without blocking the async runtime.
    fn read_block<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, FileSemanticsError>> + Send + 'a;

    /// Rechecks the identity of the same opened handle.
    fn recheck_source(&self) -> impl Future<Output = Result<(), FileSemanticsError>> + Send + '_;
}

/// A writable private transfer file before its digest is sealed.
pub trait TransferTempFile {
    /// The corresponding sealed, no-longer-writable state.
    type Sealed: SealedTransferTempFile;

    /// Writes one block and updates the running byte count and digest.
    fn write_block_async<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> impl Future<Output = Result<(), FileSemanticsError>> + Send + 'a;

    /// Flushes and synchronises the temporary file, then seals its digest.
    fn finish_async(self) -> impl Future<Output = Result<Self::Sealed, FileSemanticsError>> + Send;
}

/// A verified-ready temporary file whose only mutating operation is commit.
pub trait SealedTransferTempFile {
    /// The number of bytes written before sealing.
    fn written(&self) -> u64;

    /// Verifies the peer's terminal size and digest.
    fn verify_finish(
        &self,
        declared_size: u64,
        declared_digest: Sha256Digest,
    ) -> Result<(), FileSemanticsError>;

    /// Atomically commits without replacing an existing destination.
    fn commit_async(
        self,
        final_path: PathBuf,
    ) -> impl Future<Output = Result<(), FileSemanticsError>> + Send;
}

/// The file-system capability boundary used by transfer orchestration.
///
/// Path probing and private-file creation can block on platform file systems,
/// so the production implementation also offloads those operations. All
/// associated types remain statically dispatched on the data path.
pub trait FileTransferBackend {
    /// The opened source handle.
    type Source: TransferSource;
    /// The private destination handle.
    type Temp: TransferTempFile;

    /// Opens and validates a source through its stable handle.
    fn open_source(
        &self,
        path: PathBuf,
    ) -> impl Future<Output = Result<Self::Source, FileSemanticsError>> + Send;

    /// Resolves and probes a destination without blocking the async runtime.
    fn resolve_destination(
        &self,
        base: BaseDirectory,
        explicit_target: Option<String>,
        default_name: Option<String>,
    ) -> impl Future<Output = Result<DestinationPlan, FileSemanticsError>> + Send;

    /// Creates a private temporary file beside the final destination.
    fn create_temp(
        &self,
        directory: PathBuf,
    ) -> impl Future<Output = Result<Self::Temp, FileSemanticsError>> + Send;
}

/// Tokio's production file backend. The unit type carries no state and every
/// operation delegates to Tokio or tempfile rather than a first-party worker.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioFileTransferBackend;

/// A Tokio-backed source retaining the same opened-handle identity invariants
/// as [`SourceFile`].
pub struct TokioSourceFile {
    file: tokio::fs::File,
    initial_size: u64,
    initial_modified: Option<SystemTime>,
    read: u64,
}

impl std::fmt::Debug for TokioSourceFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokioSourceFile")
            .field("initial_size", &self.initial_size)
            .field("read", &self.read)
            .finish_non_exhaustive()
    }
}

impl TokioSourceFile {
    fn from_blocking(source: SourceFile) -> Self {
        Self {
            file: tokio::fs::File::from_std(source.file),
            initial_size: source.initial_size,
            initial_modified: source.initial_modified,
            read: source.read,
        }
    }

    fn initial_identity(&self) -> SourceIdentity {
        SourceIdentity {
            size: self.initial_size,
            modified: self.initial_modified,
        }
    }

    async fn current_identity(&self) -> Result<SourceIdentity, FileSemanticsError> {
        let metadata = self
            .file
            .metadata()
            .await
            .map_err(map_handle_metadata_error)?;
        Ok(SourceIdentity {
            size: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

impl TransferSource for TokioSourceFile {
    fn size(&self) -> u64 {
        self.initial_size
    }

    fn bytes_read(&self) -> u64 {
        self.read
    }

    async fn read_block(&mut self, buffer: &mut [u8]) -> Result<usize, FileSemanticsError> {
        let remaining = self.initial_size - self.read;
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len())
            .min(CHUNK_SIZE);
        if want == 0 {
            return Ok(0);
        }
        let n = loop {
            match self.file.read(&mut buffer[..want]).await {
                Ok(0) => break 0,
                Ok(n) => break n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(map_read_error(error)),
            }
        };
        if n == 0 {
            self.recheck_source().await?;
            return Err(FileSemanticsError::SizeMismatch {
                declared: self.initial_size,
                received: self.read,
            });
        }
        self.read += n as u64;
        Ok(n)
    }

    async fn recheck_source(&self) -> Result<(), FileSemanticsError> {
        if self
            .current_identity()
            .await?
            .changed_since(&self.initial_identity())
        {
            return Err(FileSemanticsError::SourceChanged);
        }
        Ok(())
    }
}

/// Tokio-backed private temporary file. `TempPath` keeps tempfile's
/// best-effort cleanup guard while Tokio owns the asynchronous file handle.
pub struct TokioPrivateTempFile {
    file: tokio::fs::File,
    path: TempPath,
    written: u64,
    hasher: Sha256,
}

impl std::fmt::Debug for TokioPrivateTempFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokioPrivateTempFile")
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl TokioPrivateTempFile {
    fn from_blocking(temp: PrivateTempFile) -> Self {
        let (file, path) = temp.file.into_parts();
        Self {
            file: tokio::fs::File::from_std(file),
            path,
            written: temp.written,
            hasher: temp.hasher,
        }
    }
}

impl TransferTempFile for TokioPrivateTempFile {
    type Sealed = TokioSealedTempFile;

    async fn write_block_async(&mut self, bytes: &[u8]) -> Result<(), FileSemanticsError> {
        self.file.write_all(bytes).await.map_err(map_write_error)?;
        self.written += bytes.len() as u64;
        self.hasher.update(bytes);
        Ok(())
    }

    async fn finish_async(mut self) -> Result<Self::Sealed, FileSemanticsError> {
        self.file.flush().await.map_err(map_write_error)?;
        self.file.sync_all().await.map_err(map_write_error)?;
        let digest = Sha256Digest::new(self.hasher.finalize().into());
        let file = self.file.into_std().await;
        Ok(TokioSealedTempFile {
            file: NamedTempFile::from_parts(file, self.path),
            written: self.written,
            digest,
        })
    }
}

/// Sealed Tokio temporary file. The handle is closed before this state is
/// constructed, which makes the no-clobber persistence portable to Windows.
pub struct TokioSealedTempFile {
    file: NamedTempFile,
    written: u64,
    digest: Sha256Digest,
}

impl std::fmt::Debug for TokioSealedTempFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokioSealedTempFile")
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl SealedTransferTempFile for TokioSealedTempFile {
    fn written(&self) -> u64 {
        self.written
    }

    fn verify_finish(
        &self,
        declared_size: u64,
        declared_digest: Sha256Digest,
    ) -> Result<(), FileSemanticsError> {
        if self.written != declared_size {
            return Err(FileSemanticsError::SizeMismatch {
                declared: declared_size,
                received: self.written,
            });
        }
        if self.digest != declared_digest {
            return Err(FileSemanticsError::DigestMismatch);
        }
        Ok(())
    }

    async fn commit_async(self, final_path: PathBuf) -> Result<(), FileSemanticsError> {
        if self.file.path().parent() != final_path.parent() {
            return Err(FileSemanticsError::CommitFailed(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the destination is not in the temporary file's directory",
            )));
        }
        run_file_task(move || {
            self.file
                .persist_noclobber(final_path)
                .map_err(|error| match error.error.kind() {
                    io::ErrorKind::AlreadyExists => FileSemanticsError::DestinationExists,
                    io::ErrorKind::InvalidFilename => FileSemanticsError::InvalidFileName,
                    _ => FileSemanticsError::CommitFailed(error.error),
                })
                .map(drop)
        })
        .await
    }
}

impl FileTransferBackend for TokioFileTransferBackend {
    type Source = TokioSourceFile;
    type Temp = TokioPrivateTempFile;

    async fn open_source(&self, path: PathBuf) -> Result<Self::Source, FileSemanticsError> {
        run_file_task(move || SourceFile::open(&path).map(TokioSourceFile::from_blocking)).await
    }

    async fn resolve_destination(
        &self,
        base: BaseDirectory,
        explicit_target: Option<String>,
        default_name: Option<String>,
    ) -> Result<DestinationPlan, FileSemanticsError> {
        run_file_task(move || {
            resolve_destination(&base, explicit_target.as_deref(), default_name.as_deref())
        })
        .await
    }

    async fn create_temp(&self, directory: PathBuf) -> Result<Self::Temp, FileSemanticsError> {
        run_file_task(move || {
            PrivateTempFile::create(&directory).map(TokioPrivateTempFile::from_blocking)
        })
        .await
    }
}

async fn run_file_task<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, FileSemanticsError> + Send + 'static,
) -> Result<T, FileSemanticsError> {
    tokio::task::spawn_blocking(operation).await.map_err(|_| {
        FileSemanticsError::Io(io::Error::other(
            "a file-system worker task did not complete",
        ))
    })?
}

#[cfg(test)]
impl TransferSource for SourceFile {
    fn size(&self) -> u64 {
        self.size()
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read()
    }

    async fn read_block(&mut self, buffer: &mut [u8]) -> Result<usize, FileSemanticsError> {
        self.read_chunked(buffer)
    }

    async fn recheck_source(&self) -> Result<(), FileSemanticsError> {
        self.recheck()
    }
}

/// The fixed 2.0.0 wire error code a transfer failure maps to.
///
/// The transfer layer maps the local structured failure to this code before
/// sending `Error`. `None` means a purely local failure that the peer is
/// never told about.
impl FileSemanticsError {
    #[must_use]
    pub fn wire_code(&self) -> Option<FileTransferErrorCode> {
        use FileTransferErrorCode as Code;
        match self {
            Self::SourceNotFound => Some(Code::SourceNotFound),
            Self::SourceNotRegularFile => Some(Code::SourceNotRegularFile),
            Self::DestinationExists => Some(Code::DestinationExists),
            Self::DestinationParentNotFound => Some(Code::DestinationParentNotFound),
            Self::DestinationNotDirectory => Some(Code::DestinationNotDirectory),
            Self::PermissionDenied => Some(Code::PermissionDenied),
            Self::NoSpace => Some(Code::NoSpace),
            Self::FileTooLargeForPlatform => Some(Code::FileTooLargeForPlatform),
            Self::ReadFailed(_) => Some(Code::ReadFailed),
            Self::WriteFailed(_) => Some(Code::WriteFailed),
            Self::SizeMismatch { .. } => Some(Code::SizeMismatch),
            Self::DigestMismatch => Some(Code::DigestMismatch),
            Self::SourceChanged => Some(Code::SourceChanged),
            Self::CommitFailed(_) => Some(Code::CommitFailed),
            Self::InvalidFileName => Some(Code::InvalidFileName),
            Self::InvalidRequest => Some(Code::InvalidRequest),
            Self::InvalidPathEncoding => Some(Code::InvalidPathEncoding),
            Self::PathTooLong => Some(Code::PathTooLong),
            Self::BaseDirectoryUnavailable(_) => None,
            Self::TempFileCreateFailed(_) => None,
            Self::TemporaryCleanupFailed(_) => None,
            Self::Io(_) => None,
        }
    }
}

/// Structured, type-safe failures of the file semantics layer.
///
/// Every variant is an error category aligned with the fixed 2.0.0 error
/// code table; the payload is limited to the category, the error code and
/// sizes. No variant carries a path, a file name or a temporary file name,
/// and `Debug` output never reveals them, so ordinary logs and error
/// messages stay within the design's logging rules (section 18.4).
#[derive(Debug, Error)]
pub enum FileSemanticsError {
    /// The source path does not exist (code `SourceNotFound`).
    #[error("the source file does not exist")]
    SourceNotFound,
    /// The source is not a regular file: a directory, pipe, socket, device,
    /// Windows device object or other special file (code `SourceNotRegularFile`).
    #[error("the source is not a regular file")]
    SourceNotRegularFile,
    /// The final destination already exists and is never overwritten (code
    /// `DestinationExists`).
    #[error("the destination already exists and is never overwritten")]
    DestinationExists,
    /// The parent directory of the destination does not exist and is never
    /// created automatically (code `DestinationParentNotFound`).
    #[error("the destination parent directory does not exist")]
    DestinationParentNotFound,
    /// The parent of the destination exists but is not a directory (code
    /// `DestinationNotDirectory`).
    #[error("the destination parent is not a directory")]
    DestinationNotDirectory,
    /// The operating system denied the operation (code `PermissionDenied`).
    #[error("permission denied")]
    PermissionDenied,
    /// The file system is full (code `NoSpace`).
    #[error("no space left on device")]
    NoSpace,
    /// The file is too large for this platform to express (code
    /// `FileTooLargeForPlatform`).
    #[error("the file is too large for this platform")]
    FileTooLargeForPlatform,
    /// Reading the source file failed (code `ReadFailed`).
    #[error("failed to read the source file")]
    ReadFailed(#[source] io::Error),
    /// Writing the temporary file failed (code `WriteFailed`).
    #[error("failed to write the temporary file")]
    WriteFailed(#[source] io::Error),
    /// The received byte count does not match the declared size (code
    /// `SizeMismatch`).
    #[error("the received size {received} does not match the declared size {declared}")]
    SizeMismatch {
        /// The size declared by the sender.
        declared: u64,
        /// The size actually received.
        received: u64,
    },
    /// The received digest does not match the digest of the written bytes
    /// (code `DigestMismatch`).
    #[error("the received digest does not match the computed digest")]
    DigestMismatch,
    /// The source file changed while it was being transferred (code
    /// `SourceChanged`).
    #[error("the source file changed while it was being transferred")]
    SourceChanged,
    /// The no-replace commit failed (code `CommitFailed`); the destination
    /// was not modified.
    #[error("failed to commit the temporary file to the destination")]
    CommitFailed(#[source] io::Error),
    /// The peer-provided base file name is invalid on the receiving
    /// platform and is never reinterpreted as a path (code `InvalidFileName`).
    #[error("the peer-provided default file name is invalid on this platform")]
    InvalidFileName,
    /// The request is invalid (code `InvalidRequest`).
    #[error("the request is invalid")]
    InvalidRequest,
    /// The path is not a valid protocol path (code `InvalidPathEncoding`).
    #[error("the path is not a valid protocol path")]
    InvalidPathEncoding,
    /// The path exceeds the protocol or platform length limit (code
    /// `PathTooLong`).
    #[error("the path exceeds the length limit")]
    PathTooLong,
    /// The session base directory could not be captured. Local-only: never
    /// sent to the peer.
    #[error("the session base directory is unavailable")]
    BaseDirectoryUnavailable(#[source] io::Error),
    /// The private temporary file could not be created. Local-only: never
    /// sent to the peer.
    #[error("the temporary file could not be created")]
    TempFileCreateFailed(#[source] io::Error),
    /// The temporary file could not be removed after the commit succeeded.
    /// Local-only: never sent to the peer.
    #[error("temporary file cleanup failed")]
    TemporaryCleanupFailed(#[source] io::Error),
    /// An I/O failure that does not fit a fixed category. Local-only: never
    /// sent to the peer.
    #[error("I/O failure")]
    Io(#[source] io::Error),
}

/// Computes the SHA-256 of a reader with a fixed 64 KiB buffer (design
/// 15.1): memory usage is independent of the input length.
pub fn sha256_of(reader: &mut impl Read) -> Result<Sha256Digest, FileSemanticsError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; CHUNK_SIZE];
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(FileSemanticsError::ReadFailed(error)),
        };
        hasher.update(&buffer[..n]);
    }
    Ok(Sha256Digest::new(hasher.finalize().into()))
}

/// True when a Windows path is drive-relative ("C:foo"): it has a drive
/// prefix but no root, so it resolves against that drive's working
/// directory and can never be joined under the base directory.
#[cfg(windows)]
fn is_drive_relative(path: &str) -> bool {
    let candidate = Path::new(path);
    !candidate.has_root() && matches!(candidate.components().next(), Some(Component::Prefix(_)))
}

/// Validates a path string against the protocol path rules (design 8.5):
/// UTF-8, at most `MAX_PATH_LEN` bytes, without NUL, C0/C1 control
/// characters or DEL.
fn validate_protocol_path_string(path: &str) -> Result<(), FileSemanticsError> {
    if path.len() > MAX_PATH_LEN {
        return Err(FileSemanticsError::PathTooLong);
    }
    validate_protocol_path(path.as_bytes()).map_err(|_| FileSemanticsError::InvalidPathEncoding)
}

/// Validates a peer-provided base file name with the receiving platform's
/// rules (design 8.4): the frozen wire validator plus the platform rule that
/// the name must resolve to exactly one ordinary name component: no drive
/// prefixes, no roots, no separators. On Windows, reserved device names,
/// trailing dots or spaces and colons are rejected as well.
fn validate_default_file_name_on_receiving_platform(name: &str) -> Result<(), FileSemanticsError> {
    validate_default_file_name(name).map_err(|_| FileSemanticsError::InvalidFileName)?;
    let mut components = Path::new(name).components();
    if !matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    ) {
        return Err(FileSemanticsError::InvalidFileName);
    }
    #[cfg(windows)]
    {
        // A colon cannot appear in a Win32 file name (it is the alternate
        // data stream separator) and its create-time failure is a NotFound,
        // which would otherwise be misclassified.
        if name.contains(':') {
            return Err(FileSemanticsError::InvalidFileName);
        }
    }
    Ok(())
}

fn map_temp_create_error(error: io::Error) -> FileSemanticsError {
    match error.kind() {
        io::ErrorKind::NotFound => FileSemanticsError::DestinationParentNotFound,
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
            FileSemanticsError::PermissionDenied
        }
        io::ErrorKind::StorageFull => FileSemanticsError::NoSpace,
        io::ErrorKind::FileTooLarge => FileSemanticsError::FileTooLargeForPlatform,
        io::ErrorKind::InvalidFilename => FileSemanticsError::InvalidFileName,
        _ => FileSemanticsError::TempFileCreateFailed(error),
    }
}

fn map_write_error(error: io::Error) -> FileSemanticsError {
    match error.kind() {
        io::ErrorKind::StorageFull => FileSemanticsError::NoSpace,
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
            FileSemanticsError::PermissionDenied
        }
        io::ErrorKind::FileTooLarge => FileSemanticsError::FileTooLargeForPlatform,
        io::ErrorKind::InvalidFilename => FileSemanticsError::InvalidFileName,
        _ => FileSemanticsError::WriteFailed(error),
    }
}

fn map_read_error(error: io::Error) -> FileSemanticsError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => FileSemanticsError::PermissionDenied,
        _ => FileSemanticsError::ReadFailed(error),
    }
}

#[cfg(unix)]
fn map_source_probe_error(error: io::Error) -> FileSemanticsError {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => {
            FileSemanticsError::SourceNotFound
        }
        io::ErrorKind::PermissionDenied => FileSemanticsError::PermissionDenied,
        _ => FileSemanticsError::Io(error),
    }
}

fn map_source_open_error(error: io::Error) -> FileSemanticsError {
    match error.kind() {
        io::ErrorKind::NotFound => FileSemanticsError::SourceNotFound,
        io::ErrorKind::PermissionDenied => FileSemanticsError::PermissionDenied,
        io::ErrorKind::InvalidInput => FileSemanticsError::InvalidPathEncoding,
        io::ErrorKind::InvalidFilename => FileSemanticsError::PathTooLong,
        _ => FileSemanticsError::Io(error),
    }
}

fn map_handle_metadata_error(error: io::Error) -> FileSemanticsError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => FileSemanticsError::PermissionDenied,
        _ => FileSemanticsError::Io(error),
    }
}

fn map_probe_error(error: io::Error) -> FileSemanticsError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => FileSemanticsError::PermissionDenied,
        io::ErrorKind::NotADirectory => FileSemanticsError::DestinationNotDirectory,
        io::ErrorKind::InvalidFilename => FileSemanticsError::PathTooLong,
        _ => FileSemanticsError::Io(error),
    }
}

/// Rejects Windows device objects before any system call. The standard
/// library distinguishes ordinary UNC shares from device and verbatim
/// prefixes, so `\\server\share\file` remains a valid source while `\\.\`
/// and `\\?\` namespaces are rejected. A last component that is a reserved
/// device name (for example `NUL`, `CON`, `COM1`) or ends in a dot or space
/// is rejected as well.
#[cfg(windows)]
fn reject_windows_special_sources(path: &Path) -> Result<(), FileSemanticsError> {
    if matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(
                prefix.kind(),
                Prefix::Verbatim(_)
                    | Prefix::VerbatimUNC(_, _)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::DeviceNS(_)
            )
    ) {
        return Err(FileSemanticsError::SourceNotRegularFile);
    }
    if let Some(name) = path.file_name().and_then(|name| name.to_str())
        && is_windows_reserved_file_name(name)
    {
        return Err(FileSemanticsError::SourceNotRegularFile);
    }
    Ok(())
}

/// The Win32 reserved device-name rule, mirroring the private rule of
/// `yonder_core::wire::file_transfer`: trailing dots or spaces are reserved,
/// and the stem before the first dot must not be a device name such as
/// `CON`, `NUL`, `COM1`..`COM9` or `LPT1`..`LPT9`.
#[cfg(windows)]
fn is_windows_reserved_file_name(name: &str) -> bool {
    if name.ends_with(' ') || name.ends_with('.') {
        return true;
    }
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::{Seek as _, SeekFrom, Write};
    use tempfile::tempdir;
    use tokio::io::AsyncSeekExt as _;

    // ------------------------------------------------------------------
    // Deterministic pattern helpers (bounded memory by construction).
    // ------------------------------------------------------------------

    fn pattern_byte(index: u64) -> u8 {
        ((index * 31) + (index / 251) + (index >> 3)) as u8
    }

    fn fill_pattern(buffer: &mut [u8], offset: u64) {
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = pattern_byte(offset + i as u64);
        }
    }

    fn write_pattern_file(path: &Path, size: u64) {
        let mut file = fs::File::create(path).unwrap();
        let mut buffer = [0_u8; CHUNK_SIZE];
        let mut remaining = size;
        let mut offset = 0_u64;
        while remaining > 0 {
            let n = remaining.min(CHUNK_SIZE as u64) as usize;
            fill_pattern(&mut buffer[..n], offset);
            file.write_all(&buffer[..n]).unwrap();
            remaining -= n as u64;
            offset += n as u64;
        }
        file.sync_all().unwrap();
    }

    fn pattern_digest(size: u64) -> Sha256Digest {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; CHUNK_SIZE];
        let mut remaining = size;
        let mut offset = 0_u64;
        while remaining > 0 {
            let n = remaining.min(CHUNK_SIZE as u64) as usize;
            fill_pattern(&mut buffer[..n], offset);
            hasher.update(&buffer[..n]);
            remaining -= n as u64;
            offset += n as u64;
        }
        Sha256Digest::new(hasher.finalize().into())
    }

    fn test_base(directory: &tempfile::TempDir) -> BaseDirectory {
        BaseDirectory::from_path_buf(directory.path().to_path_buf())
    }

    fn write_blocks_to_temp(
        temp: &mut PrivateTempFile,
        buffer: &mut [u8],
        size: u64,
    ) -> Result<(), FileSemanticsError> {
        let mut remaining = size;
        let mut offset = 0_u64;
        while remaining > 0 {
            let n = remaining.min(CHUNK_SIZE as u64) as usize;
            fill_pattern(&mut buffer[..n], offset);
            temp.write_block(&buffer[..n])?;
            remaining -= n as u64;
            offset += n as u64;
        }
        Ok(())
    }

    #[tokio::test]
    async fn tokio_backend_streams_verifies_and_commits_without_clobbering() {
        let directory = tempdir().unwrap();
        let source_path = directory.path().join("source.bin");
        let mut source_file = fs::File::create(&source_path).unwrap();
        let expected = (0..(CHUNK_SIZE + 17))
            .map(|index| pattern_byte(index as u64))
            .collect::<Vec<_>>();
        source_file.write_all(&expected).unwrap();
        source_file.sync_all().unwrap();
        drop(source_file);

        let backend = TokioFileTransferBackend;
        let mut source = backend.open_source(source_path).await.unwrap();
        assert_eq!(source.size(), expected.len() as u64);
        let mut received = Vec::with_capacity(expected.len());
        let mut block = [0_u8; CHUNK_SIZE];
        loop {
            let count = source.read_block(&mut block).await.unwrap();
            if count == 0 {
                break;
            }
            received.extend_from_slice(&block[..count]);
        }
        source.recheck_source().await.unwrap();
        assert_eq!(source.bytes_read(), expected.len() as u64);
        assert_eq!(received, expected);

        let plan = backend
            .resolve_destination(test_base(&directory), Some("target.bin".to_owned()), None)
            .await
            .unwrap();
        let mut temp = backend
            .create_temp(plan.temp_dir().to_path_buf())
            .await
            .unwrap();
        temp.write_block_async(&received).await.unwrap();
        let sealed = temp.finish_async().await.unwrap();
        sealed
            .verify_finish(
                received.len() as u64,
                sha256_of(&mut received.as_slice()).unwrap(),
            )
            .unwrap();
        sealed
            .commit_async(plan.final_path().to_path_buf())
            .await
            .unwrap();
        assert_eq!(fs::read(plan.final_path()).unwrap(), received);

        let second = backend
            .create_temp(plan.temp_dir().to_path_buf())
            .await
            .unwrap();
        let second = second.finish_async().await.unwrap();
        assert!(matches!(
            second.commit_async(plan.final_path().to_path_buf()).await,
            Err(FileSemanticsError::DestinationExists)
        ));
    }

    #[tokio::test]
    async fn tokio_backend_fails_closed_at_every_file_identity_and_commit_boundary() {
        let directory = tempdir().unwrap();
        let source_path = directory.path().join("source-secret.bin");
        fs::write(&source_path, b"source bytes").unwrap();
        let backend = TokioFileTransferBackend;
        let mut source = backend.open_source(source_path.clone()).await.unwrap();
        let source_debug = format!("{source:?}");
        assert!(!source_debug.contains("source-secret"));

        fs::write(&source_path, b"").unwrap();
        assert!(matches!(
            source.read_block(&mut [0_u8; CHUNK_SIZE]).await,
            Err(FileSemanticsError::SourceChanged)
        ));

        assert!(matches!(
            backend
                .open_source(directory.path().join("missing-source"))
                .await,
            Err(FileSemanticsError::SourceNotFound)
        ));
        assert!(matches!(
            backend
                .create_temp(directory.path().join("missing-directory"))
                .await,
            Err(FileSemanticsError::DestinationParentNotFound)
        ));

        let mut temp = backend
            .create_temp(directory.path().to_path_buf())
            .await
            .unwrap();
        let temp_debug = format!("{temp:?}");
        assert!(!temp_debug.contains(directory.path().to_string_lossy().as_ref()));
        let received = b"received bytes";
        let received_len = received.len() as u64;
        temp.write_block_async(received).await.unwrap();
        let sealed = temp.finish_async().await.unwrap();
        let sealed_debug = format!("{sealed:?}");
        assert!(!sealed_debug.contains(directory.path().to_string_lossy().as_ref()));
        assert!(matches!(
            sealed.verify_finish(1, sha256_of(&mut received.as_slice()).unwrap()),
            Err(FileSemanticsError::SizeMismatch {
                declared: 1,
                received
            }) if received == received_len
        ));
        assert!(matches!(
            sealed.verify_finish(received_len, Sha256Digest::new([0; 32])),
            Err(FileSemanticsError::DigestMismatch)
        ));

        let other_directory = directory.path().join("other");
        fs::create_dir(&other_directory).unwrap();
        assert!(matches!(
            sealed.commit_async(other_directory.join("target.bin")).await,
            Err(FileSemanticsError::CommitFailed(error))
                if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[tokio::test]
    async fn source_readers_fail_closed_on_early_eof_even_when_file_identity_is_unchanged() {
        let directory = tempdir().unwrap();
        let source_path = directory.path().join("source.bin");
        let payload = b"identity remains unchanged";
        fs::write(&source_path, payload).unwrap();

        let mut blocking = SourceFile::open(&source_path).unwrap();
        blocking.file.seek(SeekFrom::End(0)).unwrap();
        assert!(matches!(
            blocking.read_chunked(&mut [0_u8; CHUNK_SIZE]),
            Err(FileSemanticsError::SizeMismatch {
                declared,
                received: 0,
            }) if declared == payload.len() as u64
        ));

        let mut asynchronous = TokioFileTransferBackend
            .open_source(source_path)
            .await
            .unwrap();
        asynchronous.file.seek(SeekFrom::End(0)).await.unwrap();
        assert!(matches!(
            asynchronous.read_block(&mut [0_u8; CHUNK_SIZE]).await,
            Err(FileSemanticsError::SizeMismatch {
                declared,
                received: 0,
            }) if declared == payload.len() as u64
        ));
    }

    #[tokio::test]
    async fn file_worker_failure_is_contained_as_a_structured_io_error() {
        let error = run_file_task::<()>(|| panic!("injected file worker failure"))
            .await
            .unwrap_err();
        assert!(matches!(error, FileSemanticsError::Io(_)));
    }

    #[test]
    fn production_blocking_budget_keeps_filesystem_capacity_with_audit_active() {
        std::thread::spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(4)
                .build()
                .unwrap();
            runtime.block_on(async {
                let gate = std::sync::Arc::new(std::sync::Barrier::new(4));
                let mut bridges = Vec::new();
                for _ in 0..3 {
                    let gate = std::sync::Arc::clone(&gate);
                    bridges.push(tokio::task::spawn_blocking(move || {
                        gate.wait();
                        gate.wait();
                    }));
                }
                gate.wait();

                let directory = tempdir().unwrap();
                let records = directory.path().join("records");
                let _writer = crate::audit::writer::AuditWriter::open(
                    &records,
                    &yonder_core::wire::audit::SessionId::new([0x71; 32]),
                    yonder_core::wire::audit::AuditRole::Host,
                )
                .unwrap();
                let source_path = directory.path().join("source.bin");
                fs::write(&source_path, b"capacity remains").unwrap();
                let opened = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    TokioFileTransferBackend.open_source(source_path),
                )
                .await;

                gate.wait();
                for bridge in bridges {
                    bridge.await.unwrap();
                }
                assert!(opened.is_ok(), "Tokio filesystem work was starved");
                assert_eq!(opened.unwrap().unwrap().size(), 16);
            });
        })
        .join()
        .unwrap();
    }

    // ------------------------------------------------------------------
    // Base directory.
    // ------------------------------------------------------------------

    #[test]
    fn capture_produces_an_absolute_base_directory() {
        let base = BaseDirectory::capture().unwrap();
        assert!(base.as_path().is_absolute());
        assert_eq!(base.as_path(), std::env::current_dir().unwrap());
    }

    #[test]
    fn relative_paths_resolve_against_the_base_directory() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        assert_eq!(
            base.resolve("sub/name.txt").unwrap(),
            directory.path().join("sub").join("name.txt")
        );
        assert_eq!(
            base.resolve("üñï/with space.bin").unwrap(),
            directory.path().join("üñï").join("with space.bin")
        );
    }

    #[test]
    fn absolute_paths_are_kept_verbatim() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        let absolute = directory.path().join("elsewhere").join("f.bin");
        assert_eq!(base.resolve(absolute.to_str().unwrap()).unwrap(), absolute);
    }

    #[test]
    fn empty_resolution_and_invalid_encodings_are_rejected() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        assert!(matches!(
            base.resolve(""),
            Err(FileSemanticsError::InvalidRequest)
        ));
        assert!(matches!(
            base.resolve("bad\x00path"),
            Err(FileSemanticsError::InvalidPathEncoding)
        ));
        assert!(matches!(
            base.resolve("bad\x1fpath"),
            Err(FileSemanticsError::InvalidPathEncoding)
        ));
        assert!(matches!(
            base.resolve("bad\u{7f}path"),
            Err(FileSemanticsError::InvalidPathEncoding)
        ));
        assert!(matches!(
            base.resolve("bad\u{9f}path"),
            Err(FileSemanticsError::InvalidPathEncoding)
        ));
        let long = "a".repeat(MAX_PATH_LEN + 1);
        assert!(matches!(
            base.resolve(&long),
            Err(FileSemanticsError::PathTooLong)
        ));
        let boundary = "a".repeat(MAX_PATH_LEN);
        assert!(base.resolve(&boundary).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn drive_relative_paths_are_rejected_because_they_escape_the_base() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        // "C:foo" resolves relative to the C: drive, not to the base
        // directory; joining it would escape the base, so it is rejected.
        assert!(matches!(
            base.resolve("C:foo"),
            Err(FileSemanticsError::InvalidRequest)
        ));
        assert!(matches!(
            base.resolve("C:"),
            Err(FileSemanticsError::InvalidRequest)
        ));
        // A rooted drive path is absolute and stays verbatim.
        let drive_rooted = r"C:\yonder-probe-dir\file.txt";
        assert_eq!(base.resolve(drive_rooted).unwrap(), Path::new(drive_rooted));
    }

    #[cfg(not(windows))]
    #[test]
    fn drive_relative_strings_are_plain_relative_names_on_unix() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        assert_eq!(
            base.resolve("C:foo").unwrap(),
            directory.path().join("C:foo")
        );
    }

    // ------------------------------------------------------------------
    // Source files.
    // ------------------------------------------------------------------

    #[test]
    fn boundary_sizes_round_trip_through_source_and_receiver() {
        for size in [0_u64, 1, 65535, 65536, 65537] {
            let directory = tempdir().unwrap();
            let source_path = directory.path().join("src.bin");
            write_pattern_file(&source_path, size);

            let mut source = SourceFile::open(&source_path).unwrap();
            assert_eq!(source.size(), size);
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; CHUNK_SIZE];
            let mut total = 0_u64;
            loop {
                let n = source.read_chunked(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                assert!(n <= CHUNK_SIZE);
                hasher.update(&buffer[..n]);
                total += n as u64;
            }
            assert_eq!(total, size);
            assert_eq!(
                Sha256Digest::new(hasher.finalize().into()),
                pattern_digest(size)
            );
            assert_eq!(source.read_chunked(&mut buffer).unwrap(), 0);
            assert_eq!(source.bytes_read(), size);
            source.recheck().unwrap();
            let mut temp = PrivateTempFile::create(directory.path()).unwrap();
            assert_eq!(temp.path().parent(), Some(directory.path()));
            write_blocks_to_temp(&mut temp, &mut buffer, size).unwrap();
            assert_eq!(temp.written(), size);
            let sealed = temp.finish().unwrap();
            assert_eq!(sealed.written(), size);
            sealed.verify_finish(size, pattern_digest(size)).unwrap();
            let final_path = directory.path().join("out.bin");
            sealed.commit(&final_path).unwrap();
            assert_eq!(
                sha256_of(&mut fs::File::open(&final_path).unwrap()).unwrap(),
                pattern_digest(size)
            );
        }
    }

    #[test]
    fn an_empty_source_reads_zero_immediately() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("empty.bin");
        fs::write(&path, b"").unwrap();
        let mut source = SourceFile::open(&path).unwrap();
        assert_eq!(source.size(), 0);
        let mut buffer = [0_u8; CHUNK_SIZE];
        // Nothing was ever handed out, and the handle is never touched.
        assert_eq!(source.read_chunked(&mut buffer).unwrap(), 0);
        assert_eq!(source.bytes_read(), 0);
        assert_eq!(source.read_chunked(&mut buffer).unwrap(), 0);
        source.recheck().unwrap();
    }

    #[test]
    fn reads_never_exceed_the_initial_size_and_never_overshoot_the_chunk() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("growing.bin");
        write_pattern_file(&path, 65537);
        let mut source = SourceFile::open(&path).unwrap();
        let mut buffer = [0_u8; CHUNK_SIZE + 16];
        let first = source.read_chunked(&mut buffer).unwrap();
        assert!(first <= CHUNK_SIZE);
        // Grow the file after open; the transfer must still stop at the
        // initial size.
        let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&[0xEE; 4096]).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        let mut total = first as u64;
        loop {
            let n = source.read_chunked(&mut buffer).unwrap();
            assert!(n <= CHUNK_SIZE);
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        assert_eq!(total, 65537);
        // A small caller buffer is honored as well.
        write_pattern_file(&path, 3000);
        let mut source = SourceFile::open(&path).unwrap();
        let mut small = [0_u8; 999];
        let mut reads = 0;
        loop {
            let n = source.read_chunked(&mut small).unwrap();
            if n == 0 {
                break;
            }
            assert!(n <= 999);
            reads += 1;
        }
        assert_eq!(reads, 4); // 999 + 999 + 999 + 3
    }

    #[test]
    fn directories_and_missing_files_are_rejected() {
        let directory = tempdir().unwrap();
        let dir = directory.path().join("adir");
        fs::create_dir(&dir).unwrap();
        assert!(matches!(
            SourceFile::open(&dir),
            Err(FileSemanticsError::SourceNotRegularFile)
        ));
        assert!(matches!(
            SourceFile::open(&directory.path().join("missing.bin")),
            Err(FileSemanticsError::SourceNotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn source_probe_and_open_failures_classify_structured_errors() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir().unwrap();
        // A directory without search permission fails the path-level probe.
        let blocked = directory.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        let inside = blocked.join("f.bin");
        fs::write(&inside, b"x").unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
        match SourceFile::open(&inside) {
            Err(FileSemanticsError::PermissionDenied) => {}
            Ok(_) => {
                eprintln!("skipping: this environment ignores permission bits");
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
        // A self-referential symbolic link fails the probe with a loop
        // error, which is not one of the fixed categories.
        let loop_path = directory.path().join("loop");
        std::os::unix::fs::symlink("loop", &loop_path).unwrap();
        assert!(matches!(
            SourceFile::open(&loop_path),
            Err(FileSemanticsError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn special_files_are_rejected_on_unix() {
        for device in ["/dev/null", "/dev/zero"] {
            assert!(
                matches!(
                    SourceFile::open(Path::new(device)),
                    Err(FileSemanticsError::SourceNotRegularFile)
                ),
                "{device}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn device_namespace_paths_and_reserved_names_are_rejected_on_windows() {
        // Device and verbatim namespaces are rejected before any system
        // call; ordinary UNC shares are file-system paths, not devices.
        for path in [
            r"\\.\pipe\yonder-probe",
            r"\\.\PhysicalDrive0",
            r"\\?\C:\yonder-probe",
            r"\\?\UNC\srv\share\yonder-probe",
        ] {
            assert!(
                matches!(
                    reject_windows_special_sources(Path::new(path)),
                    Err(FileSemanticsError::SourceNotRegularFile)
                ),
                "{path}"
            );
        }
        assert!(reject_windows_special_sources(Path::new(r"\\srv\share\ordinary.bin")).is_ok());
        // Reserved device names address devices through ordinary paths.
        let directory = tempdir().unwrap();
        for name in [
            "NUL", "con.txt", "CON", "prn", "AUX", "COM1", "lpt9.x", "name.", "name ",
        ] {
            let path = directory.path().join(name);
            assert!(
                matches!(
                    SourceFile::open(&path),
                    Err(FileSemanticsError::SourceNotRegularFile)
                ),
                "{name:?}"
            );
        }
        // Names that merely resemble devices remain ordinary names.
        for name in ["console", "com10.txt", "lpt0"] {
            let path = directory.path().join(name);
            assert!(
                matches!(
                    SourceFile::open(&path),
                    Err(FileSemanticsError::SourceNotFound)
                ),
                "{name:?}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn reserved_windows_names_are_ordinary_names_on_unix() {
        let directory = tempdir().unwrap();
        for name in ["NUL", "con.txt", "name."] {
            let path = directory.path().join(name);
            assert!(
                matches!(
                    SourceFile::open(&path),
                    Err(FileSemanticsError::SourceNotFound)
                ),
                "{name:?}"
            );
        }
    }

    #[test]
    fn symbolic_links_to_regular_files_are_accepted() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("target.bin");
        write_pattern_file(&target, 12345);
        let link = directory.path().join("link.bin");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        match std::os::windows::fs::symlink_file(&target, &link) {
            Ok(()) => {}
            Err(error) => {
                // Creating a symbolic link needs the developer mode or
                // elevation; the capability is environmental, not part of
                // the module under test.
                eprintln!("skipping: cannot create a symbolic link on this system: {error}");
                return;
            }
        }
        let source = SourceFile::open(&link).unwrap();
        assert_eq!(source.size(), 12345);
        source.recheck().unwrap();
    }

    #[test]
    fn path_rebinding_does_not_replace_the_opened_source_handle() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("source.bin");
        let original = b"original source bytes";
        let replacement = b"replacement path data";
        assert_eq!(original.len(), replacement.len());
        fs::write(&path, original).unwrap();
        let mut source = SourceFile::open(&path).unwrap();
        let moved = directory.path().join("opened-source.bin");
        if let Err(error) = fs::rename(&path, &moved) {
            #[cfg(windows)]
            {
                eprintln!("skipping: this Windows filesystem cannot rename an open file: {error}");
                return;
            }
            #[cfg(not(windows))]
            panic!("failed to rebind the source path: {error}");
        }
        fs::write(&path, replacement).unwrap();

        let mut observed = vec![0_u8; original.len()];
        let read = source.read_chunked(&mut observed).unwrap();
        assert_eq!(read, original.len());
        assert_eq!(observed, original);
        source.recheck().unwrap();
        assert_eq!(fs::read(path).unwrap(), replacement);
    }

    #[test]
    fn growth_is_detected_by_the_recheck() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("f.bin");
        write_pattern_file(&path, 4096);
        let source = SourceFile::open(&path).unwrap();
        let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&[0; 64]).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        assert!(matches!(
            source.recheck(),
            Err(FileSemanticsError::SourceChanged)
        ));
    }

    #[test]
    fn shrinking_mid_transfer_fails_with_source_changed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("f.bin");
        write_pattern_file(&path, 65536);
        let mut source = SourceFile::open(&path).unwrap();
        let mut buffer = [0_u8; CHUNK_SIZE / 2];
        assert_eq!(source.read_chunked(&mut buffer).unwrap(), CHUNK_SIZE / 2);
        // Shrink the file while the handle stays open.
        let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.set_len(1024).unwrap();
        drop(writer);
        // The next read hits EOF before the initial size; the re-check of
        // the same handle reports the change.
        assert!(matches!(
            source.read_chunked(&mut buffer),
            Err(FileSemanticsError::SourceChanged)
        ));
    }

    #[test]
    fn same_size_in_place_modification_is_detected_when_the_platform_reports_it() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("f.bin");
        write_pattern_file(&path, 4096);
        let source = SourceFile::open(&path).unwrap();
        let initial = source.initial_identity();
        let mut writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(&[0xAB; 4096]).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        let current = source.current_identity().unwrap();
        let platform_detected = current.changed_since(&initial);
        let result = source.recheck();
        if platform_detected {
            assert!(matches!(result, Err(FileSemanticsError::SourceChanged)));
        } else {
            // Coarse platform time stamps (for example FAT-style 2 s
            // granularity) cannot see this modification; that is the
            // accepted boundary of design section 14, and the digest check
            // still protects the transferred content.
            assert!(result.is_ok());
        }
    }

    #[test]
    fn source_identity_change_semantics() {
        let t0 = SystemTime::UNIX_EPOCH;
        let t1 = t0 + std::time::Duration::from_secs(1);
        let initial = SourceIdentity {
            size: 10,
            modified: Some(t0),
        };
        // The getters report the recorded fields.
        assert_eq!(initial.size(), 10);
        assert_eq!(initial.modified(), Some(t0));
        assert_eq!(
            SourceIdentity {
                size: 7,
                modified: None
            }
            .modified(),
            None
        );
        assert!(!initial.changed_since(&initial));
        assert!(
            SourceIdentity {
                size: 11,
                modified: Some(t0),
            }
            .changed_since(&initial)
        );
        assert!(
            SourceIdentity {
                size: 10,
                modified: Some(t1),
            }
            .changed_since(&initial)
        );
        assert!(
            SourceIdentity {
                size: 10,
                modified: None,
            }
            .changed_since(&initial)
        );
        assert!(
            SourceIdentity {
                size: 11,
                modified: Some(t1),
            }
            .changed_since(&initial)
        );
        assert!(
            !SourceIdentity {
                size: 10,
                modified: Some(t0),
            }
            .changed_since(&initial)
        );
    }

    #[test]
    fn source_file_identity_getters_report_the_open_time_state() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("f.bin");
        write_pattern_file(&path, 1234);
        let source = SourceFile::open(&path).unwrap();
        assert_eq!(source.size(), 1234);
        assert_eq!(
            source.modified_identity(),
            source.initial_identity().modified()
        );
        assert_eq!(source.initial_identity().size(), 1234);
        // The identity re-read from the same handle matches the open-time
        // state while the file is untouched.
        assert_eq!(
            source.current_identity().unwrap(),
            source.initial_identity()
        );
        source.recheck().unwrap();
    }

    #[test]
    fn large_source_streams_with_bounded_memory() {
        const SIZE: u64 = 16 * 1024 * 1024 + 1234;
        let directory = tempdir().unwrap();
        let path = directory.path().join("large.bin");
        write_pattern_file(&path, SIZE);
        let mut source = SourceFile::open(&path).unwrap();
        assert_eq!(source.size(), SIZE);
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; CHUNK_SIZE];
        let mut total = 0_u64;
        loop {
            let n = source.read_chunked(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            assert!(n <= CHUNK_SIZE);
            hasher.update(&buffer[..n]);
            total += n as u64;
        }
        assert_eq!(total, SIZE);
        assert_eq!(
            Sha256Digest::new(hasher.finalize().into()),
            pattern_digest(SIZE)
        );
        source.recheck().unwrap();
    }

    #[test]
    fn sparse_source_beyond_4gib_reports_the_full_size() {
        const SIZE: u64 = (1_u64 << 32) + 17;
        let directory = tempdir().unwrap();
        let path = directory.path().join("huge.bin");
        let file = fs::File::create(&path).unwrap();
        file.set_len(SIZE).unwrap();
        drop(file);
        let mut source = SourceFile::open(&path).unwrap();
        assert_eq!(source.size(), SIZE);
        let mut buffer = [0_u8; CHUNK_SIZE];
        let n = source.read_chunked(&mut buffer).unwrap();
        assert!(n > 0);
        assert!(buffer[..n].iter().all(|byte| *byte == 0));
        source.recheck().unwrap();
        // The platform expresses the >4 GiB size (the 32-bit overflow
        // boundary); shrinking is detected from the same handle.
        let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.set_len(12345).unwrap();
        drop(writer);
        assert!(matches!(
            source.read_chunked(&mut buffer),
            Err(FileSemanticsError::SourceChanged)
        ));
    }

    // ------------------------------------------------------------------
    // Destination resolution.
    // ------------------------------------------------------------------

    #[test]
    fn default_destination_uses_the_base_directory() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        for explicit in [None, Some("")] {
            let plan = resolve_destination(&base, explicit, Some("peer-name.txt")).unwrap();
            assert_eq!(plan.final_path(), directory.path().join("peer-name.txt"));
            assert_eq!(plan.temp_dir(), directory.path());
        }
        // Without a peer-provided name there is no default destination.
        assert!(matches!(
            resolve_destination(&base, None, None),
            Err(FileSemanticsError::InvalidFileName)
        ));
    }

    #[test]
    fn peer_file_names_are_validated_on_the_receiving_platform() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        for name in [
            "", ".", "..", "a/b", "a\x00b", "a\x1fb", "a\u{7f}b", "a\u{9f}b",
        ] {
            assert!(
                matches!(
                    resolve_destination(&base, None, Some(name)),
                    Err(FileSemanticsError::InvalidFileName)
                ),
                "{name:?}"
            );
        }
        #[cfg(windows)]
        assert!(matches!(
            resolve_destination(&base, None, Some("a\\b")),
            Err(FileSemanticsError::InvalidFileName)
        ));
        let long = "n".repeat(1025);
        assert!(matches!(
            resolve_destination(&base, None, Some(&long)),
            Err(FileSemanticsError::InvalidFileName)
        ));
        for name in ["a.txt", "name", "with space", "üñï", "a.b.c", "com10.txt"] {
            let plan = resolve_destination(&base, None, Some(name)).unwrap();
            assert_eq!(plan.final_path(), directory.path().join(name), "{name:?}");
        }
        #[cfg(not(windows))]
        {
            // Backslash is an ordinary name character on Unix.
            let plan = resolve_destination(&base, None, Some("a\\b")).unwrap();
            assert_eq!(plan.final_path(), directory.path().join("a\\b"), "a\\b");
        }
        #[cfg(windows)]
        {
            for name in [
                "CON", "con.txt", "prn", "AUX", "NUL", "COM1", "lpt9.x", "a ", "a.", "C:", "C:foo",
                "a:b",
            ] {
                assert!(
                    matches!(
                        resolve_destination(&base, None, Some(name)),
                        Err(FileSemanticsError::InvalidFileName)
                    ),
                    "{name:?}"
                );
            }
            assert!(resolve_destination(&base, None, Some("console")).is_ok());
        }
        #[cfg(not(windows))]
        {
            // These are ordinary single-component names on Unix.
            for name in ["CON", "con.txt", "C:", "C:foo", "a:b"] {
                let plan = resolve_destination(&base, None, Some(name)).unwrap();
                assert_eq!(plan.final_path(), directory.path().join(name), "{name:?}");
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn colons_inside_default_names_are_rejected_on_windows() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        // A colon after more than one character is not a drive prefix, so
        // the single-component check passes and the receiving-platform
        // colon rule must reject the name before any system call.
        for name in ["ab:c", "1:2", "ü:ü"] {
            assert!(
                matches!(
                    resolve_destination(&base, None, Some(name)),
                    Err(FileSemanticsError::InvalidFileName)
                ),
                "{name:?}"
            );
        }
    }

    #[test]
    fn an_existing_directory_target_joins_the_peer_name() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        let out = directory.path().join("out");
        fs::create_dir(&out).unwrap();
        let plan = resolve_destination(&base, Some("out"), Some("peer.bin")).unwrap();
        assert_eq!(plan.final_path(), out.join("peer.bin"));
        assert_eq!(plan.temp_dir(), out);
    }

    #[test]
    fn an_existing_directory_target_without_or_with_invalid_names_fails() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        let out = directory.path().join("out");
        fs::create_dir(&out).unwrap();
        assert!(matches!(
            resolve_destination(&base, Some("out"), None),
            Err(FileSemanticsError::InvalidFileName)
        ));
        for name in [".", "..", "a/b"] {
            assert!(
                matches!(
                    resolve_destination(&base, Some("out"), Some(name)),
                    Err(FileSemanticsError::InvalidFileName)
                ),
                "{name:?}"
            );
        }
        #[cfg(windows)]
        assert!(matches!(
            resolve_destination(&base, Some("out"), Some("a\\b")),
            Err(FileSemanticsError::InvalidFileName)
        ));
        #[cfg(not(windows))]
        {
            // Backslash is an ordinary name character on Unix; the
            // directory target then receives it as the default name.
            let plan = resolve_destination(&base, Some("out"), Some("a\\b")).unwrap();
            assert_eq!(plan.final_path(), directory.path().join("out").join("a\\b"));
        }
        #[cfg(windows)]
        {
            assert!(matches!(
                resolve_destination(&base, Some("out"), Some("CON")),
                Err(FileSemanticsError::InvalidFileName)
            ));
        }
    }

    #[test]
    fn a_missing_explicit_target_is_the_complete_file_path() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        let plan = resolve_destination(&base, Some("name.txt"), None).unwrap();
        assert_eq!(plan.final_path(), directory.path().join("name.txt"));
        assert_eq!(plan.temp_dir(), directory.path());
        // A default name is irrelevant when the target is a complete path.
        let plan = resolve_destination(&base, Some("name.txt"), Some("ignored.bin")).unwrap();
        assert_eq!(plan.final_path(), directory.path().join("name.txt"));
        // With an existing parent, nested complete paths work as well.
        fs::create_dir(directory.path().join("sub")).unwrap();
        let plan = resolve_destination(&base, Some("sub/name.txt"), None).unwrap();
        assert_eq!(
            plan.final_path(),
            directory.path().join("sub").join("name.txt")
        );
        assert_eq!(plan.temp_dir(), directory.path().join("sub"));
    }

    #[test]
    fn existing_destination_objects_are_rejected() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        // An existing regular file as the explicit target.
        let file = directory.path().join("exists.bin");
        fs::write(&file, b"content").unwrap();
        assert!(matches!(
            resolve_destination(&base, Some("exists.bin"), None),
            Err(FileSemanticsError::DestinationExists)
        ));
        // An existing name inside an existing directory target.
        let out = directory.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("taken.bin"), b"x").unwrap();
        assert!(matches!(
            resolve_destination(&base, Some("out"), Some("taken.bin")),
            Err(FileSemanticsError::DestinationExists)
        ));
        // An existing name in the default destination directory.
        fs::write(directory.path().join("taken.bin"), b"x").unwrap();
        assert!(matches!(
            resolve_destination(&base, None, Some("taken.bin")),
            Err(FileSemanticsError::DestinationExists)
        ));
        // A symbolic link at the final path (even a dangling one) is an
        // existing object and is never replaced.
        let dangling = directory.path().join("dangling.bin");
        #[cfg(unix)]
        std::os::unix::fs::symlink(directory.path().join("ghost.bin"), &dangling).unwrap();
        #[cfg(windows)]
        match std::os::windows::fs::symlink_file(directory.path().join("ghost.bin"), &dangling) {
            Ok(()) => {}
            Err(error) => {
                eprintln!("skipping: cannot create a symbolic link on this system: {error}");
                return;
            }
        }
        assert!(matches!(
            resolve_destination(&base, Some("dangling.bin"), None),
            Err(FileSemanticsError::DestinationExists)
        ));
    }

    #[test]
    fn a_missing_parent_is_rejected_and_never_created() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        assert!(matches!(
            resolve_destination(&base, Some("no-such-dir/child.bin"), None),
            Err(FileSemanticsError::DestinationParentNotFound)
        ));
        assert!(!directory.path().join("no-such-dir").exists());
    }

    #[test]
    fn a_parent_that_is_a_file_is_rejected() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        let blocker = directory.path().join("blocker");
        fs::write(&blocker, b"not a directory").unwrap();
        assert!(matches!(
            resolve_destination(&base, Some("blocker/child.bin"), None),
            Err(FileSemanticsError::DestinationNotDirectory)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_target_without_search_permission_fails_at_the_final_path_probe() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir().unwrap();
        let locked = directory.path().join("locked");
        fs::create_dir(&locked).unwrap();
        // The directory itself is stat-able, so it resolves as a directory
        // target; probing the joined final path needs search permission
        // inside it and fails there.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
        let base = test_base(&directory);
        match resolve_destination(&base, Some("locked"), Some("peer.bin")) {
            Err(FileSemanticsError::PermissionDenied) => {}
            Ok(plan) => {
                // Elevated privileges ignore permission bits; the
                // environment, not the module, decides.
                eprintln!("skipping: this environment ignores permission bits");
                assert_eq!(plan.final_path(), locked.join("peer.bin"));
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn absolute_targets_are_kept_verbatim() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        fs::create_dir(directory.path().join("sub")).unwrap();
        let target = directory.path().join("sub").join("name.txt");
        let plan = resolve_destination(&base, Some(target.to_str().unwrap()), None).unwrap();
        assert_eq!(plan.final_path(), target);
        assert_eq!(plan.temp_dir(), target.parent().unwrap());
    }

    #[test]
    fn destination_encodings_and_lengths_are_validated() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        assert!(matches!(
            resolve_destination(&base, Some("bad\x00path"), None),
            Err(FileSemanticsError::InvalidPathEncoding)
        ));
        let long = "a".repeat(MAX_PATH_LEN + 1);
        assert!(matches!(
            resolve_destination(&base, Some(&long), None),
            Err(FileSemanticsError::PathTooLong)
        ));
        // Exactly at the protocol limit: resolution may succeed (long path
        // support enabled) or the platform may refuse the path; either way
        // the encoding is valid.
        let boundary = "a".repeat(MAX_PATH_LEN);
        let result = resolve_destination(&base, Some(&boundary), None);
        assert!(matches!(
            result,
            Ok(_) | Err(FileSemanticsError::PathTooLong)
        ));
    }

    #[test]
    fn destination_plans_are_absolute_and_consistent() {
        let directory = tempdir().unwrap();
        let base = test_base(&directory);
        fs::create_dir(directory.path().join("out")).unwrap();
        for (explicit, name) in [
            (None, Some("n.txt")),
            (Some("out"), Some("m.bin")),
            (Some("plain.bin"), None),
        ] {
            let plan = resolve_destination(&base, explicit, name).unwrap();
            assert!(plan.final_path().is_absolute());
            assert_eq!(plan.temp_dir(), plan.final_path().parent().unwrap());
        }
    }

    // ------------------------------------------------------------------
    // Private temporary files and commit.
    // ------------------------------------------------------------------

    #[test]
    fn temporary_files_are_exclusive_and_unpredictable() {
        let directory = tempdir().unwrap();
        let first = PrivateTempFile::create(directory.path()).unwrap();
        let second = PrivateTempFile::create(directory.path()).unwrap();
        assert_ne!(first.path(), second.path());
        for temp in [&first, &second] {
            assert!(temp.path().parent() == Some(directory.path()));
            assert!(fs::symlink_metadata(temp.path()).is_ok());
            assert!(!temp.path().file_name().unwrap().is_empty());
        }
    }

    #[test]
    fn temporary_file_creation_fails_cleanly() {
        let directory = tempdir().unwrap();
        // Missing directory: the destination parent is gone.
        assert!(matches!(
            PrivateTempFile::create(&directory.path().join("missing")),
            Err(FileSemanticsError::DestinationParentNotFound)
        ));
        // Tempfile owns secure name generation and exclusive creation.
        assert!(PrivateTempFile::create(directory.path()).is_ok());
    }

    #[test]
    fn write_finish_verify_and_commit() {
        let directory = tempdir().unwrap();
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, 300_000).unwrap();
        assert_eq!(temp.written(), 300_000);
        let sealed = temp.finish().unwrap();
        assert_eq!(sealed.written(), 300_000);
        assert_eq!(sealed.digest(), pattern_digest(300_000));
        // Correct Finish payload verifies.
        sealed
            .verify_finish(300_000, pattern_digest(300_000))
            .unwrap();
        // Wrong size and wrong digest are rejected before any commit.
        assert!(matches!(
            sealed.verify_finish(300_001, pattern_digest(300_000)),
            Err(FileSemanticsError::SizeMismatch {
                declared: 300_001,
                received: 300_000
            })
        ));
        let wrong_digest = Sha256Digest::new([0_u8; 32]);
        assert!(matches!(
            sealed.verify_finish(300_000, wrong_digest),
            Err(FileSemanticsError::DigestMismatch)
        ));
        // Commit lands the exact bytes at the final path and removes the
        // temporary name; the directory holds only the final file.
        let final_path = directory.path().join("out.bin");
        sealed.commit(&final_path).unwrap();
        assert_eq!(
            sha256_of(&mut fs::File::open(&final_path).unwrap()).unwrap(),
            pattern_digest(300_000)
        );
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
        let entries = fs::read_dir(directory.path())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path(), final_path);
    }

    #[test]
    fn commit_never_overwrites_a_concurrently_created_target() {
        let directory = tempdir().unwrap();
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, 4096).unwrap();
        let sealed = temp.finish().unwrap();
        // The target appears after resolution, before the commit.
        let final_path = directory.path().join("race.bin");
        fs::write(&final_path, b"ORIGINAL").unwrap();
        assert!(matches!(
            sealed.commit(&final_path),
            Err(FileSemanticsError::DestinationExists)
        ));
        // The pre-existing object is byte-identical and the temporary file
        // is gone (Drop cleanup).
        assert_eq!(fs::read(&final_path).unwrap(), b"ORIGINAL");
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn commit_rejects_a_destination_outside_the_temporary_directory() {
        let directory = tempdir().unwrap();
        let other = directory.path().join("other");
        fs::create_dir(&other).unwrap();
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, 16).unwrap();
        let sealed = temp.finish().unwrap();
        assert!(matches!(
            sealed.commit(&other.join("elsewhere.bin")),
            Err(FileSemanticsError::CommitFailed(_))
        ));
        assert!(!other.join("elsewhere.bin").exists());
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn the_sealed_temp_file_keeps_the_private_temp_file_path() {
        let directory = tempdir().unwrap();
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, 4096).unwrap();
        let sealed = temp.finish().unwrap();
        assert_eq!(sealed.path(), temp_path);
        assert_eq!(sealed.written(), 4096);
        sealed.verify_finish(4096, pattern_digest(4096)).unwrap();
        drop(sealed);
        // Dropping the sealed file removes the temporary name.
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn commit_rejects_final_names_the_platform_cannot_create() {
        let directory = tempdir().unwrap();
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, 16).unwrap();
        let sealed = temp.finish().unwrap();
        // A colon is an alternate-data-stream separator on Windows; a name
        // past the platform component limit fails on Unix.
        #[cfg(windows)]
        let final_path = directory.path().join("bad:name.bin");
        #[cfg(not(windows))]
        let final_path = directory.path().join("n".repeat(300));
        assert!(matches!(
            sealed.commit(&final_path),
            Err(FileSemanticsError::InvalidFileName)
        ));
        // Nothing was created at the final path and the temporary file was
        // cleaned up by Drop on the failure path. The directory listing is
        // used instead of probing the final path directly: on Unix an
        // over-long component makes the probe itself fail with
        // ENAMETOOLONG, which is not the NotFound this asserts.
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[cfg(windows)]
    #[test]
    fn commit_fails_when_the_directory_denies_new_file_creation() {
        let directory = tempdir().unwrap();
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, 16).unwrap();
        let sealed = temp.finish().unwrap();
        let final_path = directory.path().join("out.bin");
        // Denying new-file creation on the directory makes the no-replace
        // hard link fail; the destination is never created.
        let guard = WriteDenyGuard::new(directory.path());
        // Two environments defeat this expectation and must be detected
        // rather than failing the release gate: privileged CI agents
        // (for example with SeRestorePrivilege enabled) bypass directory
        // ACL denials entirely, and Windows CreateHardLinkW checks only
        // the target file's FILE_ADD_LINK right, not the directory's
        // add-file ACL, so the deny may not block the link at all.
        if fs::File::create(directory.path().join("probe.bin")).is_ok()
            || fs::hard_link(&temp_path, directory.path().join("probe-link.bin")).is_ok()
        {
            return;
        }
        assert!(matches!(
            sealed.commit(&final_path),
            Err(FileSemanticsError::CommitFailed(_))
        ));
        drop(guard);
        assert!(matches!(
            fs::symlink_metadata(&final_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn dropping_the_temporary_file_removes_it() {
        let directory = tempdir().unwrap();
        let temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        drop(temp);
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn large_receive_streams_with_bounded_memory_and_commits_verified_content() {
        const SIZE: u64 = 16 * 1024 * 1024 + 1234;
        let directory = tempdir().unwrap();
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, SIZE).unwrap();
        let sealed = temp.finish().unwrap();
        sealed.verify_finish(SIZE, pattern_digest(SIZE)).unwrap();
        let final_path = directory.path().join("out.bin");
        sealed.commit(&final_path).unwrap();
        assert_eq!(
            sha256_of(&mut fs::File::open(&final_path).unwrap()).unwrap(),
            pattern_digest(SIZE)
        );
        assert!(matches!(
            fs::symlink_metadata(&temp_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    // ------------------------------------------------------------------
    // Permission failures.
    // ------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_is_rejected_with_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir().unwrap();
        let blocked = directory.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o555)).unwrap();
        let result = PrivateTempFile::create(&blocked);
        if let Err(error) = result {
            assert!(
                matches!(error, FileSemanticsError::PermissionDenied),
                "{error:?}"
            );
        } else {
            // Running with elevated privileges (for example root) ignores
            // permission bits; the environment, not the module, decides.
            eprintln!("skipping: this environment ignores permission bits");
        }
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Denies write-data on a directory for `Everyone` through `icacls` and
    /// removes the ACE again on drop, so the parent temporary directory
    /// stays deletable. Only used on Windows; the owner of a directory can
    /// always change its ACL, so no elevation is required.
    #[cfg(windows)]
    struct WriteDenyGuard {
        path: PathBuf,
    }

    #[cfg(windows)]
    impl WriteDenyGuard {
        fn new(path: &Path) -> Self {
            let output = std::process::Command::new("icacls")
                .arg(path)
                .arg("/deny")
                .arg("Everyone:(WD)")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "icacls /deny failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Self {
                path: path.to_path_buf(),
            }
        }
    }

    #[cfg(windows)]
    impl Drop for WriteDenyGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("icacls")
                .arg(&self.path)
                .arg("/remove:d")
                .arg("Everyone")
                .output();
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_write_denied_directory_is_rejected_with_permission_denied() {
        let directory = tempdir().unwrap();
        let blocked = directory.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        let guard = WriteDenyGuard::new(&blocked);
        // Privileged CI agents (for example with SeRestorePrivilege
        // enabled) bypass directory ACL denials; detect that environment
        // and skip rather than failing the release gate on it.
        if fs::File::create(blocked.join("probe.bin")).is_ok() {
            return;
        }
        assert!(matches!(
            PrivateTempFile::create(&blocked),
            Err(FileSemanticsError::PermissionDenied)
        ));
        // Destination resolution requires the parent to exist and be a
        // directory, which "blocked" is; the denied write surfaces at the
        // temporary file creation, the actual permission boundary.
        let base = test_base(&directory);
        let plan = resolve_destination(&base, Some("blocked/x.bin"), None);
        assert!(
            matches!(plan, Ok(_) | Err(FileSemanticsError::PermissionDenied)),
            "{plan:?}"
        );
        if let Ok(plan) = plan {
            assert!(matches!(
                PrivateTempFile::create(plan.temp_dir()),
                Err(FileSemanticsError::PermissionDenied)
            ));
        }
        drop(guard);
        // After the ACL is removed the directory works again.
        assert!(PrivateTempFile::create(&blocked).is_ok());
    }

    // ------------------------------------------------------------------
    // Error classification, display safety and wire codes.
    // ------------------------------------------------------------------

    #[test]
    fn io_kinds_classify_into_the_fixed_categories() {
        use io::ErrorKind::{
            AlreadyExists, FileTooLarge, InvalidFilename, InvalidInput, NotADirectory, NotFound,
            Other, PermissionDenied, ReadOnlyFilesystem, StorageFull,
        };
        let kind = |kind| io::Error::new(kind, "probe");

        assert!(matches!(
            map_temp_create_error(kind(NotFound)),
            FileSemanticsError::DestinationParentNotFound
        ));
        assert!(matches!(
            map_temp_create_error(kind(PermissionDenied)),
            FileSemanticsError::PermissionDenied
        ));
        assert!(matches!(
            map_temp_create_error(kind(ReadOnlyFilesystem)),
            FileSemanticsError::PermissionDenied
        ));
        assert!(matches!(
            map_temp_create_error(kind(StorageFull)),
            FileSemanticsError::NoSpace
        ));
        assert!(matches!(
            map_temp_create_error(kind(FileTooLarge)),
            FileSemanticsError::FileTooLargeForPlatform
        ));
        assert!(matches!(
            map_temp_create_error(kind(InvalidFilename)),
            FileSemanticsError::InvalidFileName
        ));
        assert!(matches!(
            map_temp_create_error(kind(AlreadyExists)),
            FileSemanticsError::TempFileCreateFailed(_)
        ));

        assert!(matches!(
            map_write_error(kind(StorageFull)),
            FileSemanticsError::NoSpace
        ));
        assert!(matches!(
            map_write_error(kind(PermissionDenied)),
            FileSemanticsError::PermissionDenied
        ));
        assert!(matches!(
            map_write_error(kind(FileTooLarge)),
            FileSemanticsError::FileTooLargeForPlatform
        ));
        assert!(matches!(
            map_write_error(kind(NotFound)),
            FileSemanticsError::WriteFailed(_)
        ));
        assert!(matches!(
            map_write_error(kind(InvalidFilename)),
            FileSemanticsError::InvalidFileName
        ));

        assert!(matches!(
            map_read_error(kind(PermissionDenied)),
            FileSemanticsError::PermissionDenied
        ));
        assert!(matches!(
            map_read_error(kind(NotFound)),
            FileSemanticsError::ReadFailed(_)
        ));

        #[cfg(unix)]
        {
            assert!(matches!(
                map_source_probe_error(kind(NotFound)),
                FileSemanticsError::SourceNotFound
            ));
            assert!(matches!(
                map_source_probe_error(kind(NotADirectory)),
                FileSemanticsError::SourceNotFound
            ));
            assert!(matches!(
                map_source_probe_error(kind(PermissionDenied)),
                FileSemanticsError::PermissionDenied
            ));
            assert!(matches!(
                map_source_probe_error(kind(Other)),
                FileSemanticsError::Io(_)
            ));
        }

        assert!(matches!(
            map_source_open_error(kind(NotFound)),
            FileSemanticsError::SourceNotFound
        ));
        assert!(matches!(
            map_source_open_error(kind(PermissionDenied)),
            FileSemanticsError::PermissionDenied
        ));
        assert!(matches!(
            map_source_open_error(kind(InvalidFilename)),
            FileSemanticsError::PathTooLong
        ));
        assert!(matches!(
            map_source_open_error(kind(InvalidInput)),
            FileSemanticsError::InvalidPathEncoding
        ));
        assert!(matches!(
            map_source_open_error(kind(Other)),
            FileSemanticsError::Io(_)
        ));

        assert!(matches!(
            map_handle_metadata_error(kind(PermissionDenied)),
            FileSemanticsError::PermissionDenied
        ));
        assert!(matches!(
            map_handle_metadata_error(kind(Other)),
            FileSemanticsError::Io(_)
        ));

        assert!(matches!(
            map_probe_error(kind(PermissionDenied)),
            FileSemanticsError::PermissionDenied
        ));
        assert!(matches!(
            map_probe_error(kind(NotADirectory)),
            FileSemanticsError::DestinationNotDirectory
        ));
        assert!(matches!(
            map_probe_error(kind(InvalidFilename)),
            FileSemanticsError::PathTooLong
        ));
        assert!(matches!(
            map_probe_error(kind(NotFound)),
            FileSemanticsError::Io(_)
        ));
    }

    #[test]
    fn error_messages_and_debug_output_never_reveal_paths_or_names() {
        let directory = tempdir().unwrap();
        let root = directory.path().to_str().unwrap();
        let name = "secret-file-name.bin";

        let missing = SourceFile::open(&directory.path().join(name)).unwrap_err();
        let existing = {
            let path = directory.path().join(name);
            fs::write(&path, b"x").unwrap();
            resolve_destination(&test_base(&directory), None, Some(name)).unwrap_err()
        };
        let parent_missing =
            resolve_destination(&test_base(&directory), Some("no-dir/child.bin"), None)
                .unwrap_err();
        let temp = PrivateTempFile::create(directory.path()).unwrap();
        let temp_path = temp.path().to_path_buf();
        let sub = directory.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let foreign =
            resolve_destination(&test_base(&directory), Some("sub/foreign.bin"), None).unwrap();
        assert_eq!(foreign.temp_dir(), sub);
        let mut temp2 = PrivateTempFile::create(foreign.temp_dir()).unwrap();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp2, &mut buffer, 8).unwrap();
        let sealed = temp2.finish().unwrap();
        let commit_failed = sealed
            .commit(&directory.path().join("other.bin"))
            .unwrap_err();

        let synthetic = vec![
            FileSemanticsError::ReadFailed(io::Error::new(io::ErrorKind::NotFound, "probe")),
            FileSemanticsError::WriteFailed(io::Error::new(io::ErrorKind::StorageFull, "probe")),
            FileSemanticsError::CommitFailed(io::Error::new(io::ErrorKind::AlreadyExists, "probe")),
            FileSemanticsError::TemporaryCleanupFailed(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe",
            )),
            FileSemanticsError::Io(io::Error::other("probe")),
            FileSemanticsError::BaseDirectoryUnavailable(io::Error::new(
                io::ErrorKind::NotFound,
                "probe",
            )),
        ];

        for error in [missing, existing, parent_missing, commit_failed]
            .into_iter()
            .chain(synthetic)
        {
            let display = format!("{error}");
            let debug = format!("{error:?}");
            assert!(!display.contains(root), "display leaks a path: {display}");
            assert!(!debug.contains(root), "debug leaks a path: {debug}");
            assert!(!display.contains(name), "display leaks a name: {display}");
            assert!(!debug.contains(name), "debug leaks a name: {debug}");
            assert!(
                !debug.contains("secret-file-name"),
                "debug leaks a name: {debug}"
            );
        }
        // The path-holding types redact their Debug output too.
        let base = BaseDirectory::capture().unwrap();
        let debug = format!("{base:?}");
        assert_eq!(debug, "BaseDirectory([REDACTED])");
        let plan_debug = format!(
            "{:?}",
            resolve_destination(&test_base(&directory), None, Some("x")).unwrap()
        );
        assert!(!plan_debug.contains(root));
        let temp_debug = format!("{temp:?}");
        assert!(!temp_debug.contains(root));
        assert!(!temp_debug.contains(&temp_path.to_string_lossy().to_string()));
        drop(temp);
    }

    #[test]
    fn debug_output_is_redacted_to_fixed_strings() {
        let directory = tempdir().unwrap();
        let plan = resolve_destination(&test_base(&directory), None, Some("x.bin")).unwrap();
        assert_eq!(format!("{plan:?}"), "DestinationPlan { .. }");
        let mut temp = PrivateTempFile::create(directory.path()).unwrap();
        let mut buffer = [0_u8; CHUNK_SIZE];
        write_blocks_to_temp(&mut temp, &mut buffer, 16).unwrap();
        assert_eq!(format!("{temp:?}"), "PrivateTempFile { written: 16, .. }");
        let sealed = temp.finish().unwrap();
        assert_eq!(format!("{sealed:?}"), "SealedTempFile { written: 16, .. }");
        drop(sealed);
    }

    #[test]
    fn wire_codes_cover_the_fixed_error_table() {
        use FileTransferErrorCode as Code;
        let kind = |kind| io::Error::new(kind, "probe");
        let cases: &[(FileSemanticsError, Option<Code>)] = &[
            (
                FileSemanticsError::SourceNotFound,
                Some(Code::SourceNotFound),
            ),
            (
                FileSemanticsError::SourceNotRegularFile,
                Some(Code::SourceNotRegularFile),
            ),
            (
                FileSemanticsError::DestinationExists,
                Some(Code::DestinationExists),
            ),
            (
                FileSemanticsError::DestinationParentNotFound,
                Some(Code::DestinationParentNotFound),
            ),
            (
                FileSemanticsError::DestinationNotDirectory,
                Some(Code::DestinationNotDirectory),
            ),
            (
                FileSemanticsError::PermissionDenied,
                Some(Code::PermissionDenied),
            ),
            (FileSemanticsError::NoSpace, Some(Code::NoSpace)),
            (
                FileSemanticsError::FileTooLargeForPlatform,
                Some(Code::FileTooLargeForPlatform),
            ),
            (
                FileSemanticsError::ReadFailed(kind(io::ErrorKind::Other)),
                Some(Code::ReadFailed),
            ),
            (
                FileSemanticsError::WriteFailed(kind(io::ErrorKind::Other)),
                Some(Code::WriteFailed),
            ),
            (
                FileSemanticsError::SizeMismatch {
                    declared: 1,
                    received: 2,
                },
                Some(Code::SizeMismatch),
            ),
            (
                FileSemanticsError::DigestMismatch,
                Some(Code::DigestMismatch),
            ),
            (FileSemanticsError::SourceChanged, Some(Code::SourceChanged)),
            (
                FileSemanticsError::CommitFailed(kind(io::ErrorKind::Other)),
                Some(Code::CommitFailed),
            ),
            (
                FileSemanticsError::InvalidFileName,
                Some(Code::InvalidFileName),
            ),
            (
                FileSemanticsError::InvalidRequest,
                Some(Code::InvalidRequest),
            ),
            (
                FileSemanticsError::InvalidPathEncoding,
                Some(Code::InvalidPathEncoding),
            ),
            (FileSemanticsError::PathTooLong, Some(Code::PathTooLong)),
            (
                FileSemanticsError::BaseDirectoryUnavailable(kind(io::ErrorKind::Other)),
                None,
            ),
            (
                FileSemanticsError::TempFileCreateFailed(kind(io::ErrorKind::Other)),
                None,
            ),
            (
                FileSemanticsError::TemporaryCleanupFailed(kind(io::ErrorKind::Other)),
                None,
            ),
            (FileSemanticsError::Io(kind(io::ErrorKind::Other)), None),
        ];
        for (error, expected) in cases {
            assert_eq!(error.wire_code(), *expected, "{error:?}");
        }
    }

    // ------------------------------------------------------------------
    // Digest helper.
    // ------------------------------------------------------------------

    #[test]
    fn sha256_of_matches_the_standard_vectors_and_streams_with_bounded_memory() {
        let empty = sha256_of(&mut io::empty()).unwrap();
        assert_eq!(
            empty.as_bytes(),
            &[
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        let abc = sha256_of(&mut io::Cursor::new(b"abc")).unwrap();
        assert_eq!(
            abc.as_bytes(),
            &[
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        // A 1 MiB + 1 stream produces the same digest as the deterministic
        // pattern helper, whatever the internal chunking.
        let directory = tempdir().unwrap();
        let path = directory.path().join("d.bin");
        write_pattern_file(&path, 1024 * 1024 + 1);
        let digest = sha256_of(&mut fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(digest, pattern_digest(1024 * 1024 + 1));
    }

    #[test]
    fn sha256_of_propagates_read_failures() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "probe"))
            }
        }
        assert!(matches!(
            sha256_of(&mut FailingReader),
            Err(FileSemanticsError::ReadFailed(_))
        ));
    }
}
