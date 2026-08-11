//! Bounded wire messages for the Yonder native file transfer protocol.
//!
//! Every wire message uses the unified frame:
//!
//! ```text
//! 1 byte  tag
//! 4 bytes payload_length, unsigned big-endian
//! N bytes payload
//! ```
//!
//! A frame carries exactly one transfer: one file in one direction over one
//! application substream, so no transfer ID is required. Decoders validate
//! lengths before reading payloads and never allocate from peer-declared file
//! sizes.

use super::WireBytes;
use crate::error::{ProtocolError, ProtocolField};

/// The negotiated application protocol ID for native file transfer.
pub const FILE_TRANSFER_PROTOCOL: &str = "/yonder/file-transfer/2.0.0";

/// Maximum encoded protocol path length in UTF-8 bytes.
pub const MAX_PATH_LEN: usize = 4096;
/// Maximum encoded base file name length in UTF-8 bytes.
pub const MAX_FILE_NAME_LEN: usize = 1024;
/// Single data block bounds in bytes.
pub const MIN_DATA_LEN: usize = 1;
pub const MAX_DATA_LEN: usize = 65536;
/// SHA-256 digest byte length.
pub const DIGEST_LEN: usize = 32;
/// `Finish` payload: `u64` actual size plus the SHA-256 digest.
pub const FINISH_LEN: usize = 8 + DIGEST_LEN;
/// Frame header: tag plus big-endian payload length.
pub const FRAME_HEADER_LEN: usize = 5;
/// Every payload other than `Data` stays below 8 KiB.
pub const MAX_CONTROL_PAYLOAD_LEN: usize = 8192;
/// A complete framed control message: header plus the maximum control payload.
pub const MAX_CONTROL_FRAME_LEN: usize = MAX_CONTROL_PAYLOAD_LEN + FRAME_HEADER_LEN;

/// `UploadOpen`: `u16` destination length, destination, `u16` file name
/// length, file name, `u64` declared size.
pub const UPLOAD_OPEN_MAX_LEN: usize = 2 + MAX_PATH_LEN + 2 + MAX_FILE_NAME_LEN + 8;
/// `DownloadOpen`: `u16` source length, source.
pub const DOWNLOAD_OPEN_MAX_LEN: usize = 2 + MAX_PATH_LEN;
/// `DownloadOffer`: `u16` file name length, file name, `u64` declared size.
pub const DOWNLOAD_OFFER_MAX_LEN: usize = 2 + MAX_FILE_NAME_LEN + 8;

/// Fixed 2.0.0 message tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferTag {
    UploadOpen = 0x01,
    DownloadOpen = 0x02,
    DownloadOffer = 0x03,
    Ready = 0x04,
    Data = 0x05,
    Finish = 0x06,
    Committed = 0x07,
    Cancel = 0x08,
    Error = 0x09,
}

impl TransferTag {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::UploadOpen),
            0x02 => Some(Self::DownloadOpen),
            0x03 => Some(Self::DownloadOffer),
            0x04 => Some(Self::Ready),
            0x05 => Some(Self::Data),
            0x06 => Some(Self::Finish),
            0x07 => Some(Self::Committed),
            0x08 => Some(Self::Cancel),
            0x09 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Fixed 2.0.0 structured error codes. Values `0` and undefined values are
/// protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FileTransferErrorCode {
    Busy = 1,
    InvalidRequest = 2,
    InvalidPathEncoding = 3,
    InvalidFileName = 4,
    PathTooLong = 5,
    SourceNotFound = 6,
    SourceNotRegularFile = 7,
    DestinationExists = 8,
    DestinationParentNotFound = 9,
    DestinationNotDirectory = 10,
    PermissionDenied = 11,
    NoSpace = 12,
    FileTooLargeForPlatform = 13,
    ReadFailed = 14,
    WriteFailed = 15,
    SizeMismatch = 16,
    DigestMismatch = 17,
    SourceChanged = 18,
    CommitFailed = 19,
    Cancelled = 20,
    SessionClosing = 21,
    Unsupported = 22,
}

impl FileTransferErrorCode {
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Busy),
            2 => Some(Self::InvalidRequest),
            3 => Some(Self::InvalidPathEncoding),
            4 => Some(Self::InvalidFileName),
            5 => Some(Self::PathTooLong),
            6 => Some(Self::SourceNotFound),
            7 => Some(Self::SourceNotRegularFile),
            8 => Some(Self::DestinationExists),
            9 => Some(Self::DestinationParentNotFound),
            10 => Some(Self::DestinationNotDirectory),
            11 => Some(Self::PermissionDenied),
            12 => Some(Self::NoSpace),
            13 => Some(Self::FileTooLargeForPlatform),
            14 => Some(Self::ReadFailed),
            15 => Some(Self::WriteFailed),
            16 => Some(Self::SizeMismatch),
            17 => Some(Self::DigestMismatch),
            18 => Some(Self::SourceChanged),
            19 => Some(Self::CommitFailed),
            20 => Some(Self::Cancelled),
            21 => Some(Self::SessionClosing),
            22 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// A SHA-256 integrity digest carried by `Finish`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256Digest([u8; DIGEST_LEN]);

impl Sha256Digest {
    #[must_use]
    pub const fn new(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

/// One decoded file transfer message. String fields borrow the frame payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTransferMessage<'a> {
    /// Controller to host, starts an upload.
    UploadOpen {
        /// Empty means the default remote destination directory.
        destination: &'a str,
        file_name: &'a str,
        declared_size: u64,
    },
    /// Controller to host, starts a download.
    DownloadOpen { source: &'a str },
    /// Host to controller, announces the download source.
    DownloadOffer {
        file_name: &'a str,
        declared_size: u64,
    },
    /// Receiver ready after the private temporary file is created.
    Ready,
    /// One bounded file byte block.
    Data { bytes: &'a [u8] },
    /// Sender finished streaming; carries size and digest.
    Finish {
        actual_size: u64,
        digest: Sha256Digest,
    },
    /// Receiver committed the target; the only successful terminal state.
    Committed,
    /// Controller cancels the transfer.
    Cancel,
    /// Either side reports a structured failure.
    Error { code: FileTransferErrorCode },
}

impl FileTransferMessage<'_> {
    /// Encodes a control message (everything except `Data`) as a complete
    /// frame. `Data` blocks are streamed with [`encode_frame_header`] plus the
    /// raw payload and are rejected here.
    pub fn encode(&self) -> Result<WireBytes<MAX_CONTROL_FRAME_LEN>, ProtocolError> {
        let payload = match self {
            Self::UploadOpen {
                destination,
                file_name,
                declared_size,
            } => encode_upload_open(destination, file_name, *declared_size)?,
            Self::DownloadOpen { source } => encode_download_open(source)?,
            Self::DownloadOffer {
                file_name,
                declared_size,
            } => encode_download_offer(file_name, *declared_size)?,
            Self::Ready => WireBytes::new([0; MAX_CONTROL_PAYLOAD_LEN], 0),
            Self::Finish {
                actual_size,
                digest,
            } => encode_finish(*actual_size, digest),
            Self::Committed => WireBytes::new([0; MAX_CONTROL_PAYLOAD_LEN], 0),
            Self::Cancel => WireBytes::new([0; MAX_CONTROL_PAYLOAD_LEN], 0),
            Self::Error { code } => encode_error(*code),
            Self::Data { .. } => {
                return Err(ProtocolError::InvalidField(ProtocolField::FileTransferData));
            }
        };
        let mut frame = [0_u8; MAX_CONTROL_PAYLOAD_LEN + FRAME_HEADER_LEN];
        frame[..FRAME_HEADER_LEN].copy_from_slice(&encode_frame_header(
            tag_of(self),
            u32::try_from(payload.as_slice().len()).map_err(|_| ProtocolError::InvalidLength {
                expected: MAX_CONTROL_PAYLOAD_LEN,
                actual: payload.as_slice().len(),
            })?,
        ));
        frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload.as_slice().len()]
            .copy_from_slice(payload.as_slice());
        Ok(WireBytes::new(
            frame,
            FRAME_HEADER_LEN + payload.as_slice().len(),
        ))
    }

    /// Decodes one complete frame, validating the tag, the payload length
    /// bound, the exact payload structure and the absence of trailing bytes.
    pub fn decode_frame(frame: &[u8]) -> Result<FileTransferMessage<'_>, ProtocolError> {
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
}

fn tag_of(message: &FileTransferMessage<'_>) -> u8 {
    match message {
        FileTransferMessage::UploadOpen { .. } => TransferTag::UploadOpen.code(),
        FileTransferMessage::DownloadOpen { .. } => TransferTag::DownloadOpen.code(),
        FileTransferMessage::DownloadOffer { .. } => TransferTag::DownloadOffer.code(),
        FileTransferMessage::Ready => TransferTag::Ready.code(),
        FileTransferMessage::Data { .. } => TransferTag::Data.code(),
        FileTransferMessage::Finish { .. } => TransferTag::Finish.code(),
        FileTransferMessage::Committed => TransferTag::Committed.code(),
        FileTransferMessage::Cancel => TransferTag::Cancel.code(),
        FileTransferMessage::Error { .. } => TransferTag::Error.code(),
    }
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
    if TransferTag::from_byte(tag).is_none() {
        return Err(ProtocolError::UnknownTag(tag));
    }
    Ok((
        tag,
        u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
    ))
}

/// Validates a payload length against the fixed bounds of its tag before any
/// allocation or read.
pub fn validate_payload_len(tag: u8, len: usize) -> Result<(), ProtocolError> {
    let code = TransferTag::from_byte(tag).ok_or(ProtocolError::UnknownTag(tag))?;
    let valid = match code {
        // The structural minimum is 13: an empty destination plus a non-empty
        // file name of one byte plus the u64 size.
        TransferTag::UploadOpen => (13..=UPLOAD_OPEN_MAX_LEN).contains(&len),
        TransferTag::DownloadOpen => (3..=DOWNLOAD_OPEN_MAX_LEN).contains(&len),
        TransferTag::DownloadOffer => (11..=DOWNLOAD_OFFER_MAX_LEN).contains(&len),
        TransferTag::Ready => len == 0,
        TransferTag::Data => (MIN_DATA_LEN..=MAX_DATA_LEN).contains(&len),
        TransferTag::Finish => len == FINISH_LEN,
        TransferTag::Committed => len == 0,
        TransferTag::Cancel => len == 0,
        TransferTag::Error => len == 2,
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

impl FileTransferMessage<'_> {
    fn decode_payload(tag: u8, payload: &[u8]) -> Result<FileTransferMessage<'_>, ProtocolError> {
        let code = TransferTag::from_byte(tag).ok_or(ProtocolError::UnknownTag(tag))?;
        match code {
            TransferTag::UploadOpen => {
                let (destination, rest) = take_string_field(payload, 0)?;
                let (file_name, rest) = take_string_field(rest, 1)?;
                let (declared_size, rest) = take_u64(rest)?;
                if !rest.is_empty() {
                    return Err(ProtocolError::TrailingBytes);
                }
                Ok(FileTransferMessage::UploadOpen {
                    destination,
                    file_name,
                    declared_size,
                })
            }
            TransferTag::DownloadOpen => {
                let (source, rest) = take_string_field(payload, 0)?;
                if !rest.is_empty() {
                    return Err(ProtocolError::TrailingBytes);
                }
                Ok(FileTransferMessage::DownloadOpen { source })
            }
            TransferTag::DownloadOffer => {
                let (file_name, rest) = take_string_field(payload, 0)?;
                let (declared_size, rest) = take_u64(rest)?;
                if !rest.is_empty() {
                    return Err(ProtocolError::TrailingBytes);
                }
                Ok(FileTransferMessage::DownloadOffer {
                    file_name,
                    declared_size,
                })
            }
            TransferTag::Ready => Ok(FileTransferMessage::Ready),
            TransferTag::Data => Ok(FileTransferMessage::Data { bytes: payload }),
            TransferTag::Finish => {
                let (actual_size, rest) = take_u64(payload)?;
                let digest_bytes: [u8; DIGEST_LEN] =
                    rest.try_into().map_err(|_| ProtocolError::InvalidLength {
                        expected: FINISH_LEN,
                        actual: payload.len(),
                    })?;
                Ok(FileTransferMessage::Finish {
                    actual_size,
                    digest: Sha256Digest::new(digest_bytes),
                })
            }
            TransferTag::Committed => Ok(FileTransferMessage::Committed),
            TransferTag::Cancel => Ok(FileTransferMessage::Cancel),
            TransferTag::Error => {
                let code = FileTransferErrorCode::from_u16(u16::from_be_bytes(
                    payload
                        .try_into()
                        .map_err(|_| ProtocolError::InvalidLength {
                            expected: 2,
                            actual: payload.len(),
                        })?,
                ))
                .ok_or(ProtocolError::InvalidField(
                    ProtocolField::FileTransferErrorCode,
                ))?;
                Ok(FileTransferMessage::Error { code })
            }
        }
    }
}

/// Reads a `u16`-prefixed UTF-8 field. The destination field of `UploadOpen`
/// may be empty; all other string fields must be non-empty.
fn take_string_field(input: &[u8], field: u8) -> Result<(&str, &[u8]), ProtocolError> {
    let len_bytes: [u8; 2] = input
        .get(..2)
        .ok_or(ProtocolError::InvalidField(match field {
            0 => ProtocolField::FileTransferPath,
            _ => ProtocolField::FileTransferFileName,
        }))?
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength {
            expected: 2,
            actual: 0,
        })?;
    let len = usize::from(u16::from_be_bytes(len_bytes));
    let bytes = input
        .get(2..2 + len)
        .ok_or(ProtocolError::InvalidField(match field {
            0 => ProtocolField::FileTransferPath,
            _ => ProtocolField::FileTransferFileName,
        }))?;
    if field == 0 {
        validate_protocol_path(bytes)?;
    } else {
        if bytes.is_empty() {
            return Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName,
            ));
        }
        validate_protocol_path(bytes)?;
        if bytes.len() > MAX_FILE_NAME_LEN {
            return Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName,
            ));
        }
    }
    Ok((
        std::str::from_utf8(bytes)
            .map_err(|_| ProtocolError::InvalidField(ProtocolField::FileTransferPath))?,
        &input[2 + len..],
    ))
}

/// Reads a big-endian `u64` and returns the remaining input.
fn take_u64(input: &[u8]) -> Result<(u64, &[u8]), ProtocolError> {
    let bytes: [u8; 8] = input
        .get(..8)
        .ok_or(ProtocolError::InvalidField(ProtocolField::FileTransferSize))?
        .try_into()
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::FileTransferSize))?;
    Ok((u64::from_be_bytes(bytes), &input[8..]))
}

fn encode_upload_open(
    destination: &str,
    file_name: &str,
    declared_size: u64,
) -> Result<WireBytes<MAX_CONTROL_PAYLOAD_LEN>, ProtocolError> {
    let mut bytes = [0_u8; MAX_CONTROL_PAYLOAD_LEN];
    let mut len = 0;
    len = write_field(
        &mut bytes,
        len,
        destination,
        ProtocolField::FileTransferPath,
        true,
    )?;
    len = write_field(
        &mut bytes,
        len,
        file_name,
        ProtocolField::FileTransferFileName,
        false,
    )?;
    len = write_u64(&mut bytes, len, declared_size)?;
    Ok(WireBytes::new(bytes, len))
}

fn encode_download_open(source: &str) -> Result<WireBytes<MAX_CONTROL_PAYLOAD_LEN>, ProtocolError> {
    let mut bytes = [0_u8; MAX_CONTROL_PAYLOAD_LEN];
    let len = write_field(
        &mut bytes,
        0,
        source,
        ProtocolField::FileTransferPath,
        false,
    )?;
    Ok(WireBytes::new(bytes, len))
}

fn encode_download_offer(
    file_name: &str,
    declared_size: u64,
) -> Result<WireBytes<MAX_CONTROL_PAYLOAD_LEN>, ProtocolError> {
    let mut bytes = [0_u8; MAX_CONTROL_PAYLOAD_LEN];
    let mut len = write_field(
        &mut bytes,
        0,
        file_name,
        ProtocolField::FileTransferFileName,
        false,
    )?;
    len = write_u64(&mut bytes, len, declared_size)?;
    Ok(WireBytes::new(bytes, len))
}

fn encode_finish(actual_size: u64, digest: &Sha256Digest) -> WireBytes<MAX_CONTROL_PAYLOAD_LEN> {
    let mut bytes = [0_u8; MAX_CONTROL_PAYLOAD_LEN];
    bytes[..8].copy_from_slice(&actual_size.to_be_bytes());
    bytes[8..FINISH_LEN].copy_from_slice(digest.as_bytes());
    WireBytes::new(bytes, FINISH_LEN)
}

fn encode_error(code: FileTransferErrorCode) -> WireBytes<MAX_CONTROL_PAYLOAD_LEN> {
    let mut bytes = [0_u8; MAX_CONTROL_PAYLOAD_LEN];
    bytes[..2].copy_from_slice(&code.code().to_be_bytes());
    WireBytes::new(bytes, 2)
}

fn write_field(
    bytes: &mut [u8; MAX_CONTROL_PAYLOAD_LEN],
    len: usize,
    value: &str,
    field: ProtocolField,
    allow_empty: bool,
) -> Result<usize, ProtocolError> {
    if !allow_empty && value.is_empty() {
        return Err(ProtocolError::InvalidField(field));
    }
    if value.len()
        > if field == ProtocolField::FileTransferPath {
            MAX_PATH_LEN
        } else {
            MAX_FILE_NAME_LEN
        }
    {
        return Err(ProtocolError::InvalidField(field));
    }
    validate_protocol_path(value.as_bytes())?;
    let value_len = value.len();
    let prefix = (value_len as u16).to_be_bytes();
    let end = len
        .checked_add(2)
        .and_then(|v| v.checked_add(value_len))
        .ok_or(ProtocolError::InvalidField(field))?;
    bytes[len..len + 2].copy_from_slice(&prefix);
    bytes[len + 2..end].copy_from_slice(value.as_bytes());
    Ok(end)
}

fn write_u64(
    bytes: &mut [u8; MAX_CONTROL_PAYLOAD_LEN],
    len: usize,
    value: u64,
) -> Result<usize, ProtocolError> {
    let end = len
        .checked_add(8)
        .ok_or(ProtocolError::InvalidField(ProtocolField::FileTransferSize))?;
    bytes[len..end].copy_from_slice(&value.to_be_bytes());
    Ok(end)
}

/// Validates a protocol path: UTF-8, at most [`MAX_PATH_LEN`] bytes, without
/// NUL, C0/C1 control characters or DEL.
///
/// The control check is applied to decoded code points, not raw bytes:
/// UTF-8 continuation bytes legitimately fall in the `0x80..=0x9f` byte
/// range while the forbidden C1 controls are the code points
/// U+0080–U+009F.
pub fn validate_protocol_path(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.len() > MAX_PATH_LEN {
        return Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::FileTransferPath))?;
    if text.chars().any(|character| {
        let code = u32::from(character);
        code <= 0x1f || code == 0x7f || (0x80..=0x9f).contains(&code)
    }) {
        return Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath));
    }
    Ok(())
}

/// Validates a peer-provided base file name on the receiving platform.
///
/// The name must be a single ordinary name component: non-empty UTF-8, not
/// `.` or `..`, without path separators, roots, drive or UNC prefixes, and on
/// Windows also without backslashes, trailing dots/spaces or reserved device
/// names. The receiving endpoint performs this check before joining the name
/// to an existing destination directory.
pub fn validate_default_file_name(name: &str) -> Result<(), ProtocolError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(ProtocolError::InvalidField(
            ProtocolField::FileTransferFileName,
        ));
    }
    if name.len() > MAX_FILE_NAME_LEN {
        return Err(ProtocolError::InvalidField(
            ProtocolField::FileTransferFileName,
        ));
    }
    if name
        .bytes()
        .any(|byte| byte == 0x00 || byte == b'/' || byte <= 0x1f || byte == 0x7f)
        || name
            .chars()
            .any(|character| (0x80..=0x9f).contains(&u32::from(character)))
    {
        return Err(ProtocolError::InvalidField(
            ProtocolField::FileTransferFileName,
        ));
    }
    #[cfg(windows)]
    {
        // Backslash is a path separator on Windows; on Unix it is an
        // ordinary file name character.
        if name.bytes().any(|byte| byte == b'\\') || is_windows_reserved_name(name) {
            return Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName,
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reserved_name(name: &str) -> bool {
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

/// One side of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferSide {
    Controller,
    Host,
}

/// The direction of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

/// Wire-level state of one file transfer on one side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireState {
    /// Awaiting the opening message (`UploadOpen` or `DownloadOpen`).
    AwaitingOpen,
    /// The opening message was sent (`UploadOpen` or `DownloadOpen`).
    OpenSent,
    /// Download: awaiting the host's `DownloadOffer`.
    AwaitingOffer,
    /// Awaiting `Ready` after the receiver opened its private temporary file.
    AwaitingReady,
    /// Actively streaming or receiving `Data` blocks.
    Transferring,
    /// The sender sent `Finish` and awaits `Committed`.
    AwaitingCommitted,
    /// The receiver verified and committed; `Committed` was sent. Only the
    /// successful terminal state.
    Committed,
    /// The substream is closed after `Error`, `Cancel`, EOF or a protocol
    /// failure. No further messages are legal.
    Closed,
}

/// A legal-transition failure in the wire state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireStateError {
    /// The message is not legal for the current direction, side and state.
    UnexpectedMessage,
    /// The substream is already in a terminal state.
    AlreadyClosed,
}

/// Tracks the wire-level state of one transfer for one side, enforcing the
/// fixed 2.0.0 direction and ordering rules before any file I/O happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireSession {
    direction: TransferDirection,
    side: TransferSide,
    state: WireState,
}

impl WireSession {
    #[must_use]
    pub const fn new(direction: TransferDirection, side: TransferSide) -> Self {
        Self {
            direction,
            side,
            state: WireState::AwaitingOpen,
        }
    }

    #[must_use]
    pub const fn state(&self) -> WireState {
        self.state
    }

    /// Records a message the local side intends to send, validating it
    /// against the direction table and the current state.
    ///
    /// The controller may cancel at any non-terminal stage; either side may
    /// send `Error` in any non-terminal state.
    pub fn send(&mut self, message: &FileTransferMessage<'_>) -> Result<(), WireStateError> {
        match (self.direction, self.side, self.state) {
            // Controller uploads.
            (TransferDirection::Upload, TransferSide::Controller, WireState::AwaitingOpen) => {
                if matches!(message, FileTransferMessage::UploadOpen { .. }) {
                    self.state = WireState::OpenSent;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }
            (TransferDirection::Upload, TransferSide::Controller, WireState::OpenSent) => {
                match message {
                    FileTransferMessage::Ready => {
                        self.state = WireState::Transferring;
                        Ok(())
                    }
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Upload, TransferSide::Controller, WireState::Transferring) => {
                match message {
                    FileTransferMessage::Data { .. } => Ok(()),
                    FileTransferMessage::Finish { .. } => {
                        self.state = WireState::AwaitingCommitted;
                        Ok(())
                    }
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Upload, TransferSide::Controller, WireState::AwaitingCommitted) => {
                Err(WireStateError::UnexpectedMessage)
            }

            // Host uploads: sends `Ready` after the temporary file exists and
            // `Committed` only after `Finish` was received and verified.
            (TransferDirection::Upload, TransferSide::Host, WireState::AwaitingOpen) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Upload, TransferSide::Host, WireState::OpenSent) => {
                if matches!(message, FileTransferMessage::Ready) {
                    self.state = WireState::Transferring;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }
            (TransferDirection::Upload, TransferSide::Host, WireState::Transferring) => {
                if matches!(message, FileTransferMessage::Error { .. }) {
                    self.state = WireState::Closed;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }
            (TransferDirection::Upload, TransferSide::Host, WireState::AwaitingCommitted) => {
                if matches!(message, FileTransferMessage::Committed) {
                    self.state = WireState::Committed;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }

            // Controller downloads.
            (TransferDirection::Download, TransferSide::Controller, WireState::AwaitingOpen) => {
                if matches!(message, FileTransferMessage::DownloadOpen { .. }) {
                    self.state = WireState::AwaitingOffer;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }
            (TransferDirection::Download, TransferSide::Controller, WireState::AwaitingOffer) => {
                if matches!(
                    message,
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. }
                ) {
                    self.state = WireState::Closed;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }
            (TransferDirection::Download, TransferSide::Controller, WireState::AwaitingReady) => {
                match message {
                    FileTransferMessage::Ready => {
                        self.state = WireState::Transferring;
                        Ok(())
                    }
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Download, TransferSide::Controller, WireState::Transferring) => {
                match message {
                    FileTransferMessage::Data { .. } => Ok(()),
                    FileTransferMessage::Finish { .. } => {
                        self.state = WireState::AwaitingCommitted;
                        Ok(())
                    }
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (
                TransferDirection::Download,
                TransferSide::Controller,
                WireState::AwaitingCommitted,
            ) => {
                if matches!(message, FileTransferMessage::Committed) {
                    self.state = WireState::Committed;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }

            // Host downloads: sends `DownloadOffer`, then `Data` and `Finish`.
            (TransferDirection::Download, TransferSide::Host, WireState::AwaitingOpen) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Download, TransferSide::Host, WireState::OpenSent) => {
                if matches!(message, FileTransferMessage::DownloadOffer { .. }) {
                    self.state = WireState::AwaitingReady;
                    Ok(())
                } else {
                    Err(WireStateError::UnexpectedMessage)
                }
            }
            (TransferDirection::Download, TransferSide::Host, WireState::AwaitingReady) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Download, TransferSide::Host, WireState::Transferring) => {
                match message {
                    FileTransferMessage::Data { .. } => Ok(()),
                    FileTransferMessage::Finish { .. } => {
                        self.state = WireState::AwaitingCommitted;
                        Ok(())
                    }
                    FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Download, TransferSide::Host, WireState::AwaitingCommitted) => {
                Err(WireStateError::UnexpectedMessage)
            }

            _ => Err(WireStateError::AlreadyClosed),
        }
    }

    /// Records a received message, validating it against the direction table
    /// and the current state. A peer `Cancel` or `Error` closes the session
    /// from any open stage.
    pub fn receive(&mut self, message: &FileTransferMessage<'_>) -> Result<(), WireStateError> {
        match (self.direction, self.side, self.state) {
            // Controller uploads.
            (TransferDirection::Upload, TransferSide::Controller, WireState::AwaitingOpen) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Upload, TransferSide::Controller, WireState::OpenSent) => {
                match message {
                    FileTransferMessage::Ready => {
                        self.state = WireState::Transferring;
                        Ok(())
                    }
                    FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Upload, TransferSide::Controller, WireState::Transferring) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Upload, TransferSide::Controller, WireState::AwaitingCommitted) => {
                match message {
                    FileTransferMessage::Committed => {
                        self.state = WireState::Committed;
                        Ok(())
                    }
                    FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }

            // Host uploads.
            (TransferDirection::Upload, TransferSide::Host, WireState::AwaitingOpen) => {
                match message {
                    FileTransferMessage::UploadOpen { .. } => {
                        self.state = WireState::OpenSent;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Upload, TransferSide::Host, WireState::OpenSent) => match message {
                FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                    self.state = WireState::Closed;
                    Ok(())
                }
                _ => Err(WireStateError::UnexpectedMessage),
            },
            (TransferDirection::Upload, TransferSide::Host, WireState::Transferring) => {
                match message {
                    FileTransferMessage::Data { .. } => Ok(()),
                    FileTransferMessage::Finish { .. } => {
                        self.state = WireState::AwaitingCommitted;
                        Ok(())
                    }
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Upload, TransferSide::Host, WireState::AwaitingCommitted) => {
                Err(WireStateError::UnexpectedMessage)
            }

            // Controller downloads.
            (TransferDirection::Download, TransferSide::Controller, WireState::AwaitingOpen) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Download, TransferSide::Controller, WireState::AwaitingOffer) => {
                match message {
                    FileTransferMessage::DownloadOffer { .. } => {
                        self.state = WireState::AwaitingReady;
                        Ok(())
                    }
                    FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Download, TransferSide::Controller, WireState::AwaitingReady) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Download, TransferSide::Controller, WireState::Transferring) => {
                match message {
                    FileTransferMessage::Data { .. } => Ok(()),
                    FileTransferMessage::Finish { .. } => {
                        self.state = WireState::AwaitingCommitted;
                        Ok(())
                    }
                    FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (
                TransferDirection::Download,
                TransferSide::Controller,
                WireState::AwaitingCommitted,
            ) => Err(WireStateError::UnexpectedMessage),

            // Host downloads.
            (TransferDirection::Download, TransferSide::Host, WireState::AwaitingOpen) => {
                match message {
                    FileTransferMessage::DownloadOpen { .. } => {
                        self.state = WireState::OpenSent;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Download, TransferSide::Host, WireState::OpenSent) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Download, TransferSide::Host, WireState::AwaitingReady) => {
                match message {
                    FileTransferMessage::Ready => {
                        self.state = WireState::Transferring;
                        Ok(())
                    }
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }
            (TransferDirection::Download, TransferSide::Host, WireState::Transferring) => {
                Err(WireStateError::UnexpectedMessage)
            }
            (TransferDirection::Download, TransferSide::Host, WireState::AwaitingCommitted) => {
                match message {
                    FileTransferMessage::Committed => {
                        self.state = WireState::Committed;
                        Ok(())
                    }
                    FileTransferMessage::Cancel | FileTransferMessage::Error { .. } => {
                        self.state = WireState::Closed;
                        Ok(())
                    }
                    _ => Err(WireStateError::UnexpectedMessage),
                }
            }

            _ => Err(WireStateError::AlreadyClosed),
        }
    }

    /// Closes the session after a protocol failure, an error message or EOF.
    pub fn close(&mut self) {
        self.state = WireState::Closed;
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == WireState::Closed || self.state == WireState::Committed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_BYTES: [u8; DIGEST_LEN] = [7_u8; DIGEST_LEN];

    fn upload_open() -> FileTransferMessage<'static> {
        FileTransferMessage::UploadOpen {
            destination: "dir/out",
            file_name: "a.txt",
            declared_size: 5,
        }
    }

    fn finish() -> FileTransferMessage<'static> {
        FileTransferMessage::Finish {
            actual_size: 5,
            digest: Sha256Digest::new(DIGEST_BYTES),
        }
    }

    fn frame(message: &FileTransferMessage<'_>) -> Vec<u8> {
        message.encode().unwrap().as_slice().to_vec()
    }

    #[test]
    fn control_messages_round_trip() {
        let messages = [
            upload_open(),
            FileTransferMessage::DownloadOpen { source: "in/file" },
            FileTransferMessage::DownloadOffer {
                file_name: "b.bin",
                declared_size: 0,
            },
            FileTransferMessage::Ready,
            finish(),
            FileTransferMessage::Committed,
            FileTransferMessage::Cancel,
            FileTransferMessage::Error {
                code: FileTransferErrorCode::DestinationExists,
            },
        ];
        for message in messages {
            let encoded = frame(&message);
            assert_eq!(
                FileTransferMessage::decode_frame(&encoded).unwrap(),
                message,
                "round trip for {message:?}"
            );
        }
    }

    #[test]
    fn data_round_trip_via_header_and_payload() {
        let payload = [3_u8; 65536];
        let header = encode_frame_header(TransferTag::Data.code(), payload.len() as u32);
        let mut frame = header.to_vec();
        frame.extend_from_slice(&payload);
        assert_eq!(
            FileTransferMessage::decode_frame(&frame).unwrap(),
            FileTransferMessage::Data {
                bytes: &payload[..]
            }
        );
    }

    #[test]
    fn data_cannot_be_encoded_as_control() {
        let data = FileTransferMessage::Data { bytes: &[1, 2] };
        assert_eq!(
            data.encode(),
            Err(ProtocolError::InvalidField(ProtocolField::FileTransferData))
        );
    }

    #[test]
    fn empty_destination_defaults_and_empty_file_round_trip() {
        let message = FileTransferMessage::UploadOpen {
            destination: "",
            file_name: "only-name",
            declared_size: 0,
        };
        assert_eq!(
            FileTransferMessage::decode_frame(&frame(&message)).unwrap(),
            message
        );
    }

    #[test]
    fn empty_file_name_is_rejected() {
        let message = FileTransferMessage::UploadOpen {
            destination: "d",
            file_name: "",
            declared_size: 0,
        };
        assert_eq!(
            message.encode(),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName
            ))
        );
        // A hand-built, length-valid frame with an empty file name must also
        // be rejected by the field check.
        let mut payload = [0_u8; 13];
        payload[0..2].copy_from_slice(&1_u16.to_be_bytes());
        payload[2] = b'd';
        payload[3..5].copy_from_slice(&0_u16.to_be_bytes());
        payload[5..].copy_from_slice(&0_u64.to_be_bytes());
        let mut frame = encode_frame_header(TransferTag::UploadOpen.code(), 13).to_vec();
        frame.extend_from_slice(&payload);
        assert_eq!(
            FileTransferMessage::decode_frame(&frame),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName
            ))
        );
    }

    #[test]
    fn unknown_tag_is_rejected() {
        let mut frame = [0_u8; 5];
        frame[0] = 0x0a;
        assert_eq!(
            FileTransferMessage::decode_frame(&frame),
            Err(ProtocolError::UnknownTag(0x0a))
        );
        assert_eq!(
            decode_frame_header(&frame),
            Err(ProtocolError::UnknownTag(0x0a))
        );
    }

    #[test]
    fn short_and_long_headers_are_rejected() {
        assert!(matches!(
            decode_frame_header(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        let header = encode_frame_header(TransferTag::Ready.code(), 0);
        let mut long = header.to_vec();
        long.push(0);
        assert!(matches!(
            decode_frame_header(&long),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }

    #[test]
    fn payload_length_bounds_are_enforced_per_tag() {
        assert!(validate_payload_len(TransferTag::Ready.code(), 0).is_ok());
        assert!(validate_payload_len(TransferTag::Ready.code(), 1).is_err());
        assert!(validate_payload_len(TransferTag::Finish.code(), FINISH_LEN).is_ok());
        assert!(validate_payload_len(TransferTag::Finish.code(), FINISH_LEN - 1).is_err());
        assert!(validate_payload_len(TransferTag::Error.code(), 2).is_ok());
        assert!(validate_payload_len(TransferTag::Error.code(), 3).is_err());
        assert!(validate_payload_len(TransferTag::Data.code(), 1).is_ok());
        assert!(validate_payload_len(TransferTag::Data.code(), MAX_DATA_LEN).is_ok());
        assert!(validate_payload_len(TransferTag::Data.code(), 0).is_err());
        assert!(validate_payload_len(TransferTag::Data.code(), MAX_DATA_LEN + 1).is_err());
        assert!(validate_payload_len(TransferTag::UploadOpen.code(), UPLOAD_OPEN_MAX_LEN).is_ok());
        assert!(
            validate_payload_len(TransferTag::UploadOpen.code(), UPLOAD_OPEN_MAX_LEN + 1).is_err()
        );
        assert!(validate_payload_len(TransferTag::UploadOpen.code(), 12).is_err());
        assert!(
            validate_payload_len(TransferTag::DownloadOpen.code(), DOWNLOAD_OPEN_MAX_LEN).is_ok()
        );
        assert!(validate_payload_len(TransferTag::DownloadOpen.code(), 2).is_err());
        assert!(
            validate_payload_len(TransferTag::DownloadOffer.code(), DOWNLOAD_OFFER_MAX_LEN).is_ok()
        );
        assert!(validate_payload_len(TransferTag::DownloadOffer.code(), 10).is_err());
    }

    #[test]
    fn declared_length_mismatches_are_rejected() {
        let message = FileTransferMessage::UploadOpen {
            destination: "d",
            file_name: "f",
            declared_size: 1,
        };
        let mut encoded = frame(&message);
        encoded.truncate(encoded.len() - 1);
        assert!(matches!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::InvalidLength { .. })
        ));
        encoded.push(0);
        encoded.push(0);
        assert_eq!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::TrailingBytes)
        );
    }

    #[test]
    fn non_utf8_and_control_paths_are_rejected() {
        assert!(validate_protocol_path(b"ok/path").is_ok());
        assert!(validate_protocol_path(b"bad\xff").is_err());
        assert!(validate_protocol_path(b"bad\x00").is_err());
        assert!(validate_protocol_path(b"bad\x01").is_err());
        assert!(validate_protocol_path(b"bad\x7f").is_err());
        assert!(validate_protocol_path(b"bad\x9f").is_err());
        // C1 control code points are forbidden even as valid UTF-8.
        assert!(validate_protocol_path("\u{80}".as_bytes()).is_err());
        assert!(validate_protocol_path("\u{9f}".as_bytes()).is_err());
        // Multi-byte UTF-8 whose continuation bytes fall in 0x80..=0x9f is a
        // legitimate path: the C1 check is code-point based, not byte based.
        for path in ["語", "文", "目", "當", "🚀", "π", "中/漢/頭/說", "é/文/🚀"] {
            assert!(validate_protocol_path(path.as_bytes()).is_ok(), "{path}");
        }
        let long = vec![b'a'; MAX_PATH_LEN + 1];
        assert!(validate_protocol_path(&long).is_err());
        let ok = vec![b'a'; MAX_PATH_LEN];
        assert!(validate_protocol_path(&ok).is_ok());
    }

    #[test]
    fn default_file_names_are_validated() {
        for name in [
            "a.txt",
            "name",
            "with space",
            "üñï",
            "a.b.c",
            "語.txt",
            "🚀",
        ] {
            assert!(validate_default_file_name(name).is_ok(), "{name}");
        }
        for name in [
            "", ".", "..", "a/b", "a\x00b", "a\x1fb", "a\x7fb", "a\u{9f}b",
        ] {
            assert!(validate_default_file_name(name).is_err(), "{name:?}");
        }
        #[cfg(windows)]
        {
            for name in [
                "CON", "con.txt", "prn", "AUX", "NUL", "COM1", "lpt9.x", "a ", "a.", "a\\b",
            ] {
                assert!(validate_default_file_name(name).is_err(), "{name:?}");
            }
            assert!(validate_default_file_name("console").is_ok());
            assert!(validate_default_file_name("com10.txt").is_ok());
        }
        #[cfg(not(windows))]
        {
            for name in ["CON", "con.txt", "a\\b"] {
                assert!(validate_default_file_name(name).is_ok(), "{name:?}");
            }
            assert!(validate_default_file_name("a ").is_ok());
            assert!(validate_default_file_name("a.").is_ok());
        }
    }

    #[test]
    fn frame_with_declared_length_beyond_data_max_is_rejected() {
        let mut frame = [0_u8; FRAME_HEADER_LEN + 1];
        frame[0] = TransferTag::Data.code();
        frame[1..5].copy_from_slice(&(MAX_DATA_LEN as u32 + 1).to_be_bytes());
        frame[5] = 1;
        assert_eq!(
            FileTransferMessage::decode_frame(&frame),
            Err(ProtocolError::InvalidLength {
                expected: 0,
                actual: MAX_DATA_LEN + 1
            })
        );
    }

    #[test]
    fn upload_success_flow_is_legal() {
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        controller.send(&upload_open()).unwrap();
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        controller.receive(&FileTransferMessage::Ready).unwrap();
        for block in [vec![1; 5], vec![2; 65536]] {
            controller
                .send(&FileTransferMessage::Data { bytes: &block })
                .unwrap();
            host.receive(&FileTransferMessage::Data { bytes: &block })
                .unwrap();
        }
        controller.send(&finish()).unwrap();
        host.receive(&finish()).unwrap();
        host.send(&FileTransferMessage::Committed).unwrap();
        controller.receive(&FileTransferMessage::Committed).unwrap();
        assert_eq!(controller.state(), WireState::Committed);
        assert_eq!(host.state(), WireState::Committed);
        assert!(controller.is_closed());
        assert!(host.is_closed());
    }

    #[test]
    fn download_success_flow_is_legal() {
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        let open = FileTransferMessage::DownloadOpen { source: "in/f" };
        let offer = FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 3,
        };
        controller.send(&open).unwrap();
        host.receive(&open).unwrap();
        host.send(&offer).unwrap();
        controller.receive(&offer).unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        host.receive(&FileTransferMessage::Ready).unwrap();
        let block = [7_u8; 3];
        host.send(&FileTransferMessage::Data { bytes: &block })
            .unwrap();
        controller
            .receive(&FileTransferMessage::Data { bytes: &block })
            .unwrap();
        host.send(&finish()).unwrap();
        controller.receive(&finish()).unwrap();
        controller.send(&FileTransferMessage::Committed).unwrap();
        host.receive(&FileTransferMessage::Committed).unwrap();
        assert_eq!(controller.state(), WireState::Committed);
        assert_eq!(host.state(), WireState::Committed);
    }

    #[test]
    fn wrong_direction_open_is_rejected() {
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        assert_eq!(
            controller.send(&FileTransferMessage::DownloadOpen { source: "x" }),
            Err(WireStateError::UnexpectedMessage)
        );
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        assert_eq!(
            host.receive(&FileTransferMessage::DownloadOpen { source: "x" }),
            Err(WireStateError::UnexpectedMessage)
        );
        let mut download_host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        assert_eq!(
            download_host.receive(&upload_open()),
            Err(WireStateError::UnexpectedMessage)
        );
    }

    #[test]
    fn data_before_ready_is_rejected() {
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        let open = FileTransferMessage::UploadOpen {
            destination: "d",
            file_name: "f",
            declared_size: 1,
        };
        host.receive(&open).unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
    }

    #[test]
    fn duplicate_finish_is_rejected() {
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        controller.receive(&FileTransferMessage::Ready).unwrap();
        controller.send(&finish()).unwrap();
        assert_eq!(
            controller.send(&finish()),
            Err(WireStateError::UnexpectedMessage)
        );
    }

    #[test]
    fn committed_before_finish_is_rejected() {
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Committed),
            Err(WireStateError::UnexpectedMessage)
        );
    }

    #[test]
    fn host_cannot_cancel_in_download() {
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        let open = FileTransferMessage::DownloadOpen { source: "s" };
        host.receive(&open).unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        host.receive(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Cancel),
            Err(WireStateError::UnexpectedMessage)
        );
    }

    #[test]
    fn cancel_and_error_close_the_session() {
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.receive(&FileTransferMessage::Cancel).unwrap();
        assert!(host.is_closed());
        assert_eq!(
            host.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::AlreadyClosed)
        );

        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        controller
            .receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy,
            })
            .unwrap();
        assert!(controller.is_closed());
    }

    #[test]
    fn send_after_commit_is_rejected() {
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        let block = [1_u8];
        controller
            .receive(&FileTransferMessage::Data { bytes: &block })
            .unwrap();
        controller.receive(&finish()).unwrap();
        controller.send(&FileTransferMessage::Committed).unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Cancel),
            Err(WireStateError::AlreadyClosed)
        );
    }

    #[test]
    fn error_code_from_u16_maps_every_defined_code() {
        let codes = [
            (1, FileTransferErrorCode::Busy),
            (2, FileTransferErrorCode::InvalidRequest),
            (3, FileTransferErrorCode::InvalidPathEncoding),
            (4, FileTransferErrorCode::InvalidFileName),
            (5, FileTransferErrorCode::PathTooLong),
            (6, FileTransferErrorCode::SourceNotFound),
            (7, FileTransferErrorCode::SourceNotRegularFile),
            (8, FileTransferErrorCode::DestinationExists),
            (9, FileTransferErrorCode::DestinationParentNotFound),
            (10, FileTransferErrorCode::DestinationNotDirectory),
            (11, FileTransferErrorCode::PermissionDenied),
            (12, FileTransferErrorCode::NoSpace),
            (13, FileTransferErrorCode::FileTooLargeForPlatform),
            (14, FileTransferErrorCode::ReadFailed),
            (15, FileTransferErrorCode::WriteFailed),
            (16, FileTransferErrorCode::SizeMismatch),
            (17, FileTransferErrorCode::DigestMismatch),
            (18, FileTransferErrorCode::SourceChanged),
            (19, FileTransferErrorCode::CommitFailed),
            (20, FileTransferErrorCode::Cancelled),
            (21, FileTransferErrorCode::SessionClosing),
            (22, FileTransferErrorCode::Unsupported),
        ];
        for (code, expected) in codes {
            assert_eq!(
                FileTransferErrorCode::from_u16(code),
                Some(expected),
                "from_u16({code})"
            );
            assert_eq!(expected.code(), code, "{expected:?}.code()");
        }
        assert_eq!(FileTransferErrorCode::from_u16(0), None);
        assert_eq!(FileTransferErrorCode::from_u16(23), None);
        assert_eq!(FileTransferErrorCode::from_u16(u16::MAX), None);
        // Every defined code also round-trips through a wire Error frame.
        for (code, expected) in codes {
            let message = FileTransferMessage::Error { code: expected };
            assert_eq!(
                FileTransferMessage::decode_frame(&frame(&message)).unwrap(),
                message,
                "error code {code} round trip"
            );
        }
    }

    #[test]
    fn frame_shorter_than_header_is_rejected() {
        for len in 0..FRAME_HEADER_LEN {
            let short = vec![0_u8; len];
            assert_eq!(
                FileTransferMessage::decode_frame(&short),
                Err(ProtocolError::InvalidLength {
                    expected: FRAME_HEADER_LEN,
                    actual: len,
                }),
                "frame of {len} bytes"
            );
        }
    }

    #[test]
    fn payload_trailing_bytes_are_rejected_for_each_open_message() {
        // UploadOpen: destination "d", file name "f", size 1, plus one stray
        // byte after the exact field layout.
        let mut payload = vec![];
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.push(b'd');
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.push(b'f');
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.push(0xAA);
        let mut encoded =
            encode_frame_header(TransferTag::UploadOpen.code(), payload.len() as u32).to_vec();
        encoded.extend_from_slice(&payload);
        assert_eq!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::TrailingBytes)
        );

        // DownloadOpen: source "s" plus one stray byte.
        let mut payload = vec![];
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.push(b's');
        payload.push(0xAA);
        let mut encoded =
            encode_frame_header(TransferTag::DownloadOpen.code(), payload.len() as u32).to_vec();
        encoded.extend_from_slice(&payload);
        assert_eq!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::TrailingBytes)
        );

        // DownloadOffer: file name "f", size 1, plus one stray byte.
        let mut payload = vec![];
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.push(b'f');
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.push(0xAA);
        let mut encoded =
            encode_frame_header(TransferTag::DownloadOffer.code(), payload.len() as u32).to_vec();
        encoded.extend_from_slice(&payload);
        assert_eq!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::TrailingBytes)
        );
    }

    #[test]
    fn decode_payload_rejects_wrong_finish_and_error_lengths() {
        // Finish payloads shorter than the u64 size field.
        for len in 0..8 {
            assert_eq!(
                FileTransferMessage::decode_payload(TransferTag::Finish.code(), &vec![0_u8; len]),
                Err(ProtocolError::InvalidField(ProtocolField::FileTransferSize)),
                "finish payload len {len}"
            );
        }
        // Finish payloads with fewer than DIGEST_LEN bytes after the size.
        for len in 8..FINISH_LEN {
            assert_eq!(
                FileTransferMessage::decode_payload(TransferTag::Finish.code(), &vec![0_u8; len]),
                Err(ProtocolError::InvalidLength {
                    expected: FINISH_LEN,
                    actual: len,
                }),
                "finish payload len {len}"
            );
        }
        // Error payloads must be exactly two bytes.
        for len in [0, 1, 3] {
            assert_eq!(
                FileTransferMessage::decode_payload(TransferTag::Error.code(), &vec![0_u8; len]),
                Err(ProtocolError::InvalidLength {
                    expected: 2,
                    actual: len,
                }),
                "error payload len {len}"
            );
        }
        // An exact-length Finish still decodes.
        let mut payload = [0_u8; FINISH_LEN];
        payload[8..].copy_from_slice(&DIGEST_BYTES);
        assert_eq!(
            FileTransferMessage::decode_payload(TransferTag::Finish.code(), &payload),
            Ok(FileTransferMessage::Finish {
                actual_size: 0,
                digest: Sha256Digest::new(DIGEST_BYTES),
            })
        );
    }

    #[test]
    fn undefined_error_codes_are_rejected_as_invalid_fields() {
        for code in [0_u16, 23, u16::MAX] {
            assert_eq!(
                FileTransferMessage::decode_payload(TransferTag::Error.code(), &code.to_be_bytes()),
                Err(ProtocolError::InvalidField(
                    ProtocolField::FileTransferErrorCode
                )),
                "undefined error code {code}"
            );
        }
        // The public frame path reports the same for code 0.
        let mut encoded = encode_frame_header(TransferTag::Error.code(), 2).to_vec();
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferErrorCode
            ))
        );
    }

    #[test]
    fn short_and_oversized_declared_fields_are_rejected() {
        // Input shorter than the two length bytes.
        let inputs: [&[u8]; 2] = [&[], &[0_u8]];
        for payload in inputs {
            assert_eq!(
                FileTransferMessage::decode_payload(TransferTag::UploadOpen.code(), payload),
                Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath)),
                "payload {payload:?}"
            );
        }
        // A declared destination length beyond the remaining input.
        let payload = [0xff, 0xff, 0x00];
        assert_eq!(
            FileTransferMessage::decode_payload(TransferTag::UploadOpen.code(), &payload),
            Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath))
        );
        // The same for the file-name field after a valid destination.
        let mut payload = vec![];
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.push(b'd');
        payload.extend_from_slice(&0xffff_u16.to_be_bytes());
        assert_eq!(
            FileTransferMessage::decode_payload(TransferTag::UploadOpen.code(), &payload),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName
            ))
        );
        // The public frame path: DownloadOpen declaring 65535 bytes.
        let mut encoded = encode_frame_header(TransferTag::DownloadOpen.code(), 3).to_vec();
        encoded.extend_from_slice(&[0xff, 0xff, 0x00]);
        assert_eq!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath))
        );
    }

    #[test]
    fn overlong_file_name_is_rejected_when_decoding() {
        let name = vec![b'a'; MAX_FILE_NAME_LEN + 1];
        let mut payload = vec![];
        payload.extend_from_slice(&0_u16.to_be_bytes()); // empty destination
        payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
        payload.extend_from_slice(&name);
        payload.extend_from_slice(&0_u64.to_be_bytes());
        let mut encoded =
            encode_frame_header(TransferTag::UploadOpen.code(), payload.len() as u32).to_vec();
        encoded.extend_from_slice(&payload);
        assert_eq!(
            FileTransferMessage::decode_frame(&encoded),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName
            ))
        );
    }

    #[test]
    fn encode_rejects_overlong_and_empty_fields() {
        let overlong_name = "a".repeat(MAX_FILE_NAME_LEN + 1);
        assert_eq!(
            FileTransferMessage::DownloadOffer {
                file_name: &overlong_name,
                declared_size: 0,
            }
            .encode(),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName
            ))
        );
        let overlong_path = "p".repeat(MAX_PATH_LEN + 1);
        assert_eq!(
            FileTransferMessage::DownloadOpen {
                source: &overlong_path
            }
            .encode(),
            Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath))
        );
        assert_eq!(
            FileTransferMessage::DownloadOpen { source: "" }.encode(),
            Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath))
        );
        assert_eq!(
            FileTransferMessage::DownloadOffer {
                file_name: "",
                declared_size: 0,
            }
            .encode(),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName
            ))
        );
        // A control character in a path is rejected by the encoder too.
        assert_eq!(
            FileTransferMessage::UploadOpen {
                destination: "bad\x00dir",
                file_name: "f",
                declared_size: 0,
            }
            .encode(),
            Err(ProtocolError::InvalidField(ProtocolField::FileTransferPath))
        );
    }

    #[test]
    fn tag_of_data_is_the_wire_data_tag() {
        assert_eq!(
            tag_of(&FileTransferMessage::Data { bytes: &[1, 2] }),
            TransferTag::Data.code()
        );
    }

    #[test]
    fn overlong_default_file_name_is_rejected() {
        assert_eq!(
            validate_default_file_name(&"a".repeat(MAX_FILE_NAME_LEN + 1)),
            Err(ProtocolError::InvalidField(
                ProtocolField::FileTransferFileName
            ))
        );
        assert!(validate_default_file_name(&"a".repeat(MAX_FILE_NAME_LEN)).is_ok());
        for bad in [
            "a\u{80}b", "a\u{85}b", "a\u{9f}b", "a\u{1c}b", "a\u{7f}b", "a\u{0}b",
        ] {
            assert_eq!(
                validate_default_file_name(bad),
                Err(ProtocolError::InvalidField(
                    ProtocolField::FileTransferFileName
                )),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn upload_controller_send_side_transitions() {
        // OpenSent: Data before Ready is rejected.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::OpenSent);
        // OpenSent: Cancel and Error close the session.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        assert_eq!(controller.send(&FileTransferMessage::Cancel), Ok(()));
        assert_eq!(controller.state(), WireState::Closed);
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy
            }),
            Ok(())
        );
        assert_eq!(controller.state(), WireState::Closed);
        // OpenSent: Ready advances the implemented state machine, although
        // §10.3 assigns Ready to the host only.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        assert_eq!(controller.send(&FileTransferMessage::Ready), Ok(()));
        assert_eq!(controller.state(), WireState::Transferring);
        // Transferring: illegal messages are rejected without a transition.
        assert_eq!(
            controller.send(&FileTransferMessage::Committed),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::Transferring);
        // Transferring: Cancel closes the session.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        controller.receive(&FileTransferMessage::Ready).unwrap();
        assert_eq!(controller.send(&FileTransferMessage::Cancel), Ok(()));
        assert_eq!(controller.state(), WireState::Closed);
        // Transferring: Error closes the session.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        controller.receive(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Error {
                code: FileTransferErrorCode::ReadFailed
            }),
            Ok(())
        );
        assert_eq!(controller.state(), WireState::Closed);
    }

    #[test]
    fn upload_host_send_side_transitions() {
        // The host may not send anything before receiving UploadOpen.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        assert_eq!(
            host.send(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingOpen);
        // In Transferring the host may only send Error.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::Transferring);
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Error {
                code: FileTransferErrorCode::ReadFailed
            }),
            Ok(())
        );
        assert_eq!(host.state(), WireState::Closed);
        // In AwaitingCommitted the host may only send Committed.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        host.receive(&finish()).unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingCommitted);
    }

    #[test]
    fn upload_receive_side_illegal_transitions() {
        // Controller: nothing may be received while AwaitingOpen.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        assert_eq!(
            controller.receive(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingOpen);
        // Controller in OpenSent accepts only Ready and Error.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::OpenSent);
        // Controller in Transferring may receive nothing.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        controller.receive(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::Transferring);
        // Controller in AwaitingCommitted accepts Committed and Error only.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        controller.receive(&FileTransferMessage::Ready).unwrap();
        controller.send(&finish()).unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingCommitted);
        // Error while awaiting Committed closes the session.
        let mut controller = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        controller.send(&upload_open()).unwrap();
        controller.receive(&FileTransferMessage::Ready).unwrap();
        controller.send(&finish()).unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::WriteFailed
            }),
            Ok(())
        );
        assert_eq!(controller.state(), WireState::Closed);
    }

    #[test]
    fn upload_host_receive_side_illegal_transitions() {
        // Host in AwaitingOpen accepts only UploadOpen.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        assert_eq!(
            host.receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy
            }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingOpen);
        // Host in Transferring accepts Data, Finish, Cancel and Error only.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::Transferring);
        // Error in Transferring closes the session.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::ReadFailed
            }),
            Ok(())
        );
        assert_eq!(host.state(), WireState::Closed);
        // Cancel in Transferring closes the session.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(host.receive(&FileTransferMessage::Cancel), Ok(()));
        assert_eq!(host.state(), WireState::Closed);
        // Host in AwaitingCommitted may receive nothing.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.send(&FileTransferMessage::Ready).unwrap();
        host.receive(&finish()).unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingCommitted);
    }

    #[test]
    fn download_controller_send_side_transitions() {
        // AwaitingOpen: only DownloadOpen may be sent.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        assert_eq!(
            controller.send(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy
            }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingOpen);
        // AwaitingOffer: Cancel closes the session.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        assert_eq!(controller.send(&FileTransferMessage::Cancel), Ok(()));
        assert_eq!(controller.state(), WireState::Closed);
        // AwaitingOffer: Error closes the session.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy
            }),
            Ok(())
        );
        assert_eq!(controller.state(), WireState::Closed);
        // AwaitingOffer: other messages are rejected.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingOffer);
        // AwaitingReady: Data before Ready is rejected.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingReady);
        // AwaitingReady: Cancel closes the session.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        assert_eq!(controller.send(&FileTransferMessage::Cancel), Ok(()));
        assert_eq!(controller.state(), WireState::Closed);
        // Transferring: the implemented state machine also accepts Data and
        // Finish from the download controller (§10.3 does not list them),
        // rejects other messages, and lets Cancel/Error close the session.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Data { bytes: &[1] }),
            Ok(())
        );
        assert_eq!(controller.state(), WireState::Transferring);
        assert_eq!(
            controller.send(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::Transferring);
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(controller.send(&finish()), Ok(()));
        assert_eq!(controller.state(), WireState::AwaitingCommitted);
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(controller.send(&FileTransferMessage::Cancel), Ok(()));
        assert_eq!(controller.state(), WireState::Closed);
        // AwaitingCommitted: no further sends are legal.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        controller.receive(&finish()).unwrap();
        assert_eq!(
            controller.send(&FileTransferMessage::Cancel),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingCommitted);
    }

    #[test]
    fn download_controller_receive_side_transitions() {
        // AwaitingOpen: nothing may be received.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        assert_eq!(
            controller.receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingOpen);
        // AwaitingOffer: Error closes the session.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::SourceNotFound
            }),
            Ok(())
        );
        assert_eq!(controller.state(), WireState::Closed);
        // AwaitingOffer: other messages are rejected.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingOffer);
        // AwaitingReady: Data before Ready is rejected.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingReady);
        // Transferring: Error closes the session.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::ReadFailed
            }),
            Ok(())
        );
        assert_eq!(controller.state(), WireState::Closed);
        // Transferring: other messages are rejected.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::Transferring);
        // AwaitingCommitted: nothing may be received.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        controller.receive(&finish()).unwrap();
        assert_eq!(
            controller.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(controller.state(), WireState::AwaitingCommitted);
    }

    #[test]
    fn download_host_send_side_transitions() {
        // The host may not send before receiving DownloadOpen.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        assert_eq!(
            host.send(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingOpen);
        // In OpenSent only DownloadOffer may be sent.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::OpenSent);
        // In AwaitingReady nothing may be sent.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingReady);
        // Error mid-transfer closes the session.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        host.receive(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Error {
                code: FileTransferErrorCode::ReadFailed
            }),
            Ok(())
        );
        assert_eq!(host.state(), WireState::Closed);
        // In AwaitingCommitted nothing may be sent.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        host.receive(&FileTransferMessage::Ready).unwrap();
        host.send(&finish()).unwrap();
        assert_eq!(
            host.send(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingCommitted);
    }

    #[test]
    fn download_host_receive_side_transitions() {
        // In OpenSent nothing may be received.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Ready),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::OpenSent);
        // In AwaitingReady, Cancel closes the session.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        assert_eq!(host.receive(&FileTransferMessage::Cancel), Ok(()));
        assert_eq!(host.state(), WireState::Closed);
        // In AwaitingReady, Error closes the session.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy
            }),
            Ok(())
        );
        assert_eq!(host.state(), WireState::Closed);
        // In AwaitingReady, Data is rejected.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingReady);
        // In Transferring nothing may be received.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        host.receive(&FileTransferMessage::Ready).unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::Transferring);
        // In AwaitingCommitted, Cancel closes the session and other messages
        // are rejected.
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        host.receive(&FileTransferMessage::Ready).unwrap();
        host.send(&finish()).unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Data { bytes: &[1] }),
            Err(WireStateError::UnexpectedMessage)
        );
        assert_eq!(host.state(), WireState::AwaitingCommitted);
        let mut host = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host.receive(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        host.send(&FileTransferMessage::DownloadOffer {
            file_name: "f",
            declared_size: 1,
        })
        .unwrap();
        host.receive(&FileTransferMessage::Ready).unwrap();
        host.send(&finish()).unwrap();
        assert_eq!(
            host.receive(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy
            }),
            Ok(())
        );
        assert_eq!(host.state(), WireState::Closed);
    }

    #[test]
    fn messages_after_close_and_commit_are_rejected() {
        // Send and receive after a Cancel-closed session.
        let mut host = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        host.receive(&upload_open()).unwrap();
        host.receive(&FileTransferMessage::Cancel).unwrap();
        assert_eq!(host.state(), WireState::Closed);
        assert_eq!(
            host.send(&FileTransferMessage::Error {
                code: FileTransferErrorCode::Busy
            }),
            Err(WireStateError::AlreadyClosed)
        );
        assert_eq!(
            host.receive(&FileTransferMessage::Ready),
            Err(WireStateError::AlreadyClosed)
        );
        // Receive after the successful Committed state.
        let mut controller =
            WireSession::new(TransferDirection::Download, TransferSide::Controller);
        controller
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        controller
            .receive(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 1,
            })
            .unwrap();
        controller.send(&FileTransferMessage::Ready).unwrap();
        controller.receive(&finish()).unwrap();
        controller.send(&FileTransferMessage::Committed).unwrap();
        assert_eq!(controller.state(), WireState::Committed);
        assert_eq!(
            controller.receive(&FileTransferMessage::Committed),
            Err(WireStateError::AlreadyClosed)
        );
        assert_eq!(
            controller.receive(&FileTransferMessage::Cancel),
            Err(WireStateError::AlreadyClosed)
        );
    }
}
