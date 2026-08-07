//! Native file-transfer file semantics for the 0.1.3 controller and host
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
//!   creates an unpredictable, exclusively-created file next to the final
//!   path (the name is drawn from the project-wide [`SecureRandom`] source
//!   and creation uses `create_new`, so an existing name is never followed).
//!   Bytes are written with a streamed SHA-256 running in lock-step; on
//!   [`PrivateTempFile::finish`] the file is flushed and synchronised, and
//!   [`SealedTempFile::verify_finish`] enforces the declared size and digest.
//!   The final commit is a no-replace operation: on platforms where a
//!   no-replace rename is unavailable, an exclusive hard link plus removal of
//!   the temporary name is used, so an existing final object fails the commit
//!   and is never replaced, truncated or deleted first (section 13). If the
//!   file system cannot provide such a commit (for example a file system
//!   without hard links), the transfer fails with
//!   [`FileSemanticsError::CommitFailed`] as the design requires. The
//!   temporary file is removed on every failure path via `Drop`.
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
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use yonder_core::SecureRandom;
use yonder_core::wire::file_transfer::{
    FileTransferErrorCode, MAX_PATH_LEN, Sha256Digest, validate_default_file_name,
    validate_protocol_path,
};

/// The fixed streaming buffer size in bytes: file I/O, wire blocks and digest
/// computation all work in chunks of at most this size (design 15.1).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// How many fresh random names are attempted before temporary file creation
/// fails. Collisions with 128-bit names are effectively impossible; the bound
/// only exists so a pathological random source cannot loop forever.
const TEMP_NAME_ATTEMPTS: usize = 8;

/// The prefix of every private temporary file name. The prefix is not
/// sensitive; the entropy is in the 128 random bits that follow it.
const TEMP_FILE_PREFIX: &str = ".yonder-tmp-";

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
    /// non-blocking open flag. The probe never judges the transfer object —
    /// type and size are still taken exclusively from the opened handle
    /// (design 8.2). On Windows, paths in the device, verbatim or UNC
    /// namespace (`\\`-leading paths) and paths whose last component is a
    /// reserved device name (for example `NUL`, `CON`, `COM1`) are rejected
    /// before any system call, because such names name device objects, not
    /// files.
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
                    // refusal from the path (only as a classification aid —
                    // the handle remains the sole authority when an open
                    // succeeds).
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
/// The name is unpredictable (128 bits from the injected [`SecureRandom`]
/// source) and the file is created with exclusive `create_new`, so an
/// existing name is never followed or opened. Bytes are written with a
/// streamed SHA-256 running in lock-step. The file is removed on `Drop`,
/// covering failures, cancellation and process exit as far as best-effort
/// cleanup can (design section 13).
pub struct PrivateTempFile {
    file: fs::File,
    written: u64,
    hasher: Sha256,
    guard: TempFileGuard,
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
    /// Creates a private temporary file in `directory` with an unpredictable
    /// name. `directory` must exist (typically [`DestinationPlan::temp_dir`]).
    ///
    /// Creation failures are classified: a missing directory is
    /// [`FileSemanticsError::DestinationParentNotFound`], denied permission
    /// or a read-only file system is [`FileSemanticsError::PermissionDenied`],
    /// a full file system is [`FileSemanticsError::NoSpace`], and everything
    /// else is [`FileSemanticsError::TempFileCreateFailed`]. A failing
    /// random source fails the creation; there is no weak fallback.
    pub fn create(
        directory: &Path,
        random: &mut impl SecureRandom,
    ) -> Result<Self, FileSemanticsError> {
        let mut name_bytes = [0_u8; 16];
        for _ in 0..TEMP_NAME_ATTEMPTS {
            random
                .try_fill(&mut name_bytes)
                .map_err(|_| FileSemanticsError::TempFileCreateFailed(random_failure()))?;
            let path = directory.join(temp_file_name(&name_bytes));
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        written: 0,
                        hasher: Sha256::new(),
                        guard: TempFileGuard { path },
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_temp_create_error(error)),
            }
        }
        Err(FileSemanticsError::TempFileCreateFailed(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary file name collisions exceeded the retry limit",
        )))
    }

    /// The temporary file's path. It must never be logged.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.guard.path
    }

    /// The number of bytes written so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Streams one block into the temporary file, updating the running byte
    /// count and SHA-256. Blocks are typically at most [`CHUNK_SIZE`] bytes.
    pub fn write_block(&mut self, bytes: &[u8]) -> Result<(), FileSemanticsError> {
        self.file.write_all(bytes).map_err(map_write_error)?;
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
        self.file.flush().map_err(map_write_error)?;
        self.file.sync_all().map_err(map_write_error)?;
        let digest = Sha256Digest::new(self.hasher.finalize().into());
        Ok(SealedTempFile {
            file: self.file,
            written: self.written,
            digest,
            guard: self.guard,
        })
    }
}

/// A finished, flushed private temporary file that can no longer be written.
///
/// Created by [`PrivateTempFile::finish`]; the two-type split makes it
/// impossible to write after the digest was sealed. The temporary file is
/// removed on `Drop` if it still exists.
pub struct SealedTempFile {
    file: fs::File,
    written: u64,
    digest: Sha256Digest,
    guard: TempFileGuard,
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
        &self.guard.path
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
        let temp_path = self.guard.path.clone();
        if temp_path.parent() != final_path.parent() {
            return Err(FileSemanticsError::CommitFailed(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the destination is not in the temporary file's directory",
            )));
        }
        drop(self.file);
        if let Err(error) = fs::hard_link(&temp_path, final_path) {
            return Err(match error.kind() {
                io::ErrorKind::AlreadyExists => FileSemanticsError::DestinationExists,
                io::ErrorKind::InvalidFilename => FileSemanticsError::InvalidFileName,
                _ => FileSemanticsError::CommitFailed(error),
            });
        }
        fs::remove_file(&temp_path).map_err(FileSemanticsError::TemporaryCleanupFailed)?;
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

/// Best-effort removal of the temporary file when the owning value is
/// dropped, regardless of how the transfer ended (design section 13).
struct TempFileGuard {
    path: PathBuf,
}

impl std::fmt::Debug for TempFileGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TempFileGuard([REDACTED])")
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        // The path may already be committed and removed; a NotFound here is
        // the success case, and any other error is deliberately ignored on
        // the drop path (best effort only).
        let _ = fs::remove_file(&self.path);
    }
}

/// The fixed 1.0.0 wire error code a transfer failure maps to.
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
/// Every variant is an error category aligned with the fixed 1.0.0 error
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
/// the name must resolve to exactly one ordinary name component — no drive
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

fn temp_file_name(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(TEMP_FILE_PREFIX.len() + 2 * bytes.len());
    name.push_str(TEMP_FILE_PREFIX);
    for byte in bytes {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 0x0f) as usize] as char);
    }
    name
}

fn random_failure() -> io::Error {
    io::Error::other("the operating system secure random source failed")
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

/// Rejects Windows device objects before any system call: any `\\`-leading
/// path is in the UNC, device or verbatim namespace (which names pipes,
/// devices and raw volumes, not files), and a last component that is a
/// reserved device name (for example `NUL`, `CON`, `COM1`) or ends in a dot
/// or space addresses a device through ordinary path resolution. Files with
/// such names cannot be created through normal Win32 paths, so no legitimate
/// file is ever blocked.
#[cfg(windows)]
fn reject_windows_special_sources(path: &Path) -> Result<(), FileSemanticsError> {
    if let Some(text) = path.to_str() {
        if text.starts_with(r"\\") {
            return Err(FileSemanticsError::SourceNotRegularFile);
        }
        if let Some(name) = path.file_name().and_then(|name| name.to_str())
            && is_windows_reserved_file_name(name)
        {
            return Err(FileSemanticsError::SourceNotRegularFile);
        }
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
    use std::io::Write;
    use tempfile::tempdir;
    use yonder_core::{OsSecureRandom, RandomError};

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

    // ------------------------------------------------------------------
    // Deterministic random sources for the tests.
    // ------------------------------------------------------------------

    /// Fills with a byte from a sequence; the last value repeats forever.
    #[derive(Clone)]
    struct FixedRandom(Vec<u8>);

    impl FixedRandom {
        fn new(values: &[u8]) -> Self {
            Self(values.to_vec())
        }

        fn repeat(value: u8) -> Self {
            Self(vec![value])
        }
    }

    impl SecureRandom for FixedRandom {
        fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
            let value = if self.0.len() > 1 {
                self.0.remove(0)
            } else {
                self.0[0]
            };
            destination.fill(value);
            Ok(())
        }
    }

    struct FailingRandom;

    impl SecureRandom for FailingRandom {
        fn try_fill(&mut self, _destination: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError)
        }
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

            let mut random = OsSecureRandom;
            let mut temp = PrivateTempFile::create(directory.path(), &mut random).unwrap();
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
        // Any \\-leading path is a UNC, device or verbatim path; these must
        // be rejected before any system call (no device, pipe or network
        // access is attempted).
        for path in [
            r"\\.\pipe\yonder-probe",
            r"\\.\PhysicalDrive0",
            r"\\?\C:\yonder-probe",
            r"\\srv\share\yonder-probe",
        ] {
            assert!(
                matches!(
                    SourceFile::open(Path::new(path)),
                    Err(FileSemanticsError::SourceNotRegularFile)
                ),
                "{path}"
            );
        }
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
        let mut random = OsSecureRandom;
        let first = PrivateTempFile::create(directory.path(), &mut random).unwrap();
        let second = PrivateTempFile::create(directory.path(), &mut random).unwrap();
        assert_ne!(first.path(), second.path());
        for temp in [&first, &second] {
            assert!(temp.path().parent() == Some(directory.path()));
            assert!(fs::symlink_metadata(temp.path()).is_ok());
            let name = temp.path().file_name().unwrap().to_str().unwrap();
            assert!(name.starts_with(TEMP_FILE_PREFIX));
            assert!(name.len() == TEMP_FILE_PREFIX.len() + 32);
            assert!(
                name[TEMP_FILE_PREFIX.len()..]
                    .chars()
                    .all(|c| c.is_ascii_hexdigit())
            );
        }
    }

    #[test]
    fn temporary_file_creation_fails_cleanly() {
        let directory = tempdir().unwrap();
        let mut random = OsSecureRandom;
        // Missing directory: the destination parent is gone.
        assert!(matches!(
            PrivateTempFile::create(&directory.path().join("missing"), &mut random),
            Err(FileSemanticsError::DestinationParentNotFound)
        ));
        // Failing random source: no weak fallback, structured failure.
        assert!(matches!(
            PrivateTempFile::create(directory.path(), &mut FailingRandom),
            Err(FileSemanticsError::TempFileCreateFailed(_))
        ));
    }

    #[test]
    fn temporary_file_creation_retries_on_name_collisions() {
        let directory = tempdir().unwrap();
        // The first two fills produce the same name (collision on the
        // second creation), the third one a fresh name.
        let mut random = FixedRandom::new(&[0, 0, 1]);
        let first = PrivateTempFile::create(directory.path(), &mut random).unwrap();
        let second = PrivateTempFile::create(directory.path(), &mut random).unwrap();
        assert_ne!(first.path(), second.path());
    }

    #[test]
    fn temporary_file_creation_gives_up_after_persistent_collisions() {
        let directory = tempdir().unwrap();
        let mut random = FixedRandom::repeat(7);
        let first = PrivateTempFile::create(directory.path(), &mut random).unwrap();
        assert!(matches!(
            PrivateTempFile::create(directory.path(), &mut random),
            Err(FileSemanticsError::TempFileCreateFailed(_))
        ));
        // The first file is untouched.
        assert!(fs::symlink_metadata(first.path()).is_ok());
    }

    #[test]
    fn write_finish_verify_and_commit() {
        let directory = tempdir().unwrap();
        let mut random = OsSecureRandom;
        let mut temp = PrivateTempFile::create(directory.path(), &mut random).unwrap();
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
        let mut random = OsSecureRandom;
        let mut temp = PrivateTempFile::create(directory.path(), &mut random).unwrap();
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
        let mut random = OsSecureRandom;
        let mut temp = PrivateTempFile::create(directory.path(), &mut random).unwrap();
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
    fn dropping_the_temporary_file_removes_it() {
        let directory = tempdir().unwrap();
        let mut random = OsSecureRandom;
        let temp = PrivateTempFile::create(directory.path(), &mut random).unwrap();
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
        let mut random = OsSecureRandom;
        let mut temp = PrivateTempFile::create(directory.path(), &mut random).unwrap();
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
        let mut random = OsSecureRandom;
        let result = PrivateTempFile::create(&blocked, &mut random);
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
        let mut random = OsSecureRandom;
        assert!(matches!(
            PrivateTempFile::create(&blocked, &mut random),
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
            let mut random = OsSecureRandom;
            assert!(matches!(
                PrivateTempFile::create(plan.temp_dir(), &mut random),
                Err(FileSemanticsError::PermissionDenied)
            ));
        }
        drop(guard);
        // After the ACL is removed the directory works again.
        let mut random = OsSecureRandom;
        assert!(PrivateTempFile::create(&blocked, &mut random).is_ok());
    }

    // ------------------------------------------------------------------
    // Error classification, display safety and wire codes.
    // ------------------------------------------------------------------

    #[test]
    fn io_kinds_classify_into_the_fixed_categories() {
        use io::ErrorKind::{
            AlreadyExists, FileTooLarge, InvalidFilename, NotADirectory, NotFound,
            PermissionDenied, ReadOnlyFilesystem, StorageFull,
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
        let mut random = OsSecureRandom;
        let temp = PrivateTempFile::create(directory.path(), &mut random).unwrap();
        let temp_path = temp.path().to_path_buf();
        let sub = directory.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let foreign =
            resolve_destination(&test_base(&directory), Some("sub/foreign.bin"), None).unwrap();
        assert_eq!(foreign.temp_dir(), sub);
        let mut temp2 = PrivateTempFile::create(foreign.temp_dir(), &mut random).unwrap();
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
