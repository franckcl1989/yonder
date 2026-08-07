//! Local control input state machine (0.1.3 design §6.1–§6.4, §7.4–§7.6, §16.1).
//!
//! Interprets the local control namespace on controller terminal input: the
//! `Ctrl+]` prefix and its selectors in pass-through, the modal file-transfer
//! input rules during path prompts and transfers, and full transparency for
//! non-interactive input.
//!
//! The machine is pure and deterministic: it performs no I/O, allocates
//! nothing, and every output buffer has a fixed compile-time capacity, so the
//! module needs no runtime error handling on the processing path.

/// Fixed capacity of one local input chunk and of the path and remainder
/// output buffers. Must not exceed the terminal input chunk bound.
pub const INPUT_CAPACITY: usize = 4096;

/// Worst-case remote output for one chunk: the input capacity plus one
/// carried-over escape byte whose selector arrives in the next chunk.
pub const REMOTE_CAPACITY: usize = INPUT_CAPACITY + 1;

/// `Ctrl+]`, the local control prefix byte.
const LOCAL_ESCAPE: u8 = 0x1d;

/// `Ctrl+C`, the direct modal cancellation byte (§6.3, §16.1, §16.2).
const CANCEL_BYTE: u8 = 0x03;

/// Failures at the local control input boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalControlError {
    /// A chunk length larger than the fixed input capacity was requested.
    ChunkLengthExceedsCapacity,
    /// A transition that requires an active file operation was requested
    /// while no file operation was active.
    NoActiveModal,
}

impl std::fmt::Display for LocalControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChunkLengthExceedsCapacity => {
                f.write_str("local input chunk length exceeds the fixed capacity")
            }
            Self::NoActiveModal => f.write_str("no local file operation is active"),
        }
    }
}

impl std::error::Error for LocalControlError {}

/// The local action the coordinator must take after processing one input
/// chunk. When several local events occur in one chunk, the last one wins;
/// [`LocalAction::Detach`], [`LocalAction::CancelOp`] and the `u`/`d`
/// selectors stop processing the rest of their chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalAction {
    /// Pure forwarding: no local action.
    #[default]
    None,
    /// `Ctrl+] .` in pass-through or modal: end the whole terminal session
    /// (§6.2, §6.3, §16.3). The machine enters its ended state.
    Detach,
    /// `Ctrl+] u`: enter the upload interaction. The machine is now modal in
    /// the upload prompt phase.
    StartUpload,
    /// `Ctrl+] d`: enter the download interaction. The machine is now modal
    /// in the download prompt phase.
    StartDownload,
    /// `Ctrl+] ?`: display the local control help (§7.6). In pass-through the
    /// rest of the chunk resumes ordinary forwarding; in modal the machine
    /// stays in its current phase.
    ShowHelp,
    /// `Ctrl+] u` or `Ctrl+] d` while a file operation is already active:
    /// report "file transfer already active" and keep the operation (§6.3).
    AlreadyActive,
    /// `Ctrl+C` in modal: cancel the current file operation. Never forwarded
    /// to the remote terminal (§6.3, §16.1, §16.2).
    CancelOp,
    /// Modal: an unrecognized or abandoned prefix selector (including
    /// `Ctrl+] Ctrl+]` and `Ctrl+] <other>`) — ring the terminal BEL and
    /// ignore (§6.3). Also the single bell allowed for the first paused
    /// ordinary input during a transfer (§7.5).
    Bell,
}

/// The phase of an active file operation, which defines the input semantics
/// of the modal state (§6.3, §7.4, §7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalPhase {
    /// Path prompt of an upload. Ordinary bytes are path editor input.
    UploadPrompt,
    /// Path prompt of a download. Ordinary bytes are path editor input.
    DownloadPrompt,
    /// The actual file transfer: ordinary input is paused, not forwarded,
    /// not queued and never replayed; the first dropped input may ring one
    /// BEL (§7.5).
    Transferring,
}

/// A fixed-capacity byte buffer that always exposes a valid view.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedBytes<const CAP: usize> {
    bytes: [u8; CAP],
    len: usize,
}

impl<const CAP: usize> Default for BoundedBytes<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> BoundedBytes<CAP> {
    fn new() -> Self {
        Self {
            bytes: [0; CAP],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, byte: u8) {
        debug_assert!(self.len < CAP, "bounded buffer overflow");
        self.bytes[self.len] = byte;
        self.len += 1;
    }

    fn extend(&mut self, bytes: &[u8]) {
        debug_assert!(self.len + bytes.len() <= CAP, "bounded buffer overflow");
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }
}

/// Bytes produced for forwarding to the remote terminal. Empty while the
/// machine is modal. Capacity: [`REMOTE_CAPACITY`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteBytes(BoundedBytes<REMOTE_CAPACITY>);

impl RemoteBytes {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Ordinary bytes typed while a modal path prompt is active; handed to the
/// local path editor (§7.4). Capacity: [`INPUT_CAPACITY`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathBytes(BoundedBytes<INPUT_CAPACITY>);

impl PathBytes {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Bytes of the same chunk that follow a recognized `u` or `d` selector;
/// they belong to the newly started local file operation, in original order,
/// and must never be sent to the remote terminal (§6.2). Capacity:
/// [`INPUT_CAPACITY`]; at most `INPUT_CAPACITY - 2` bytes can ever be present.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemainderBytes(BoundedBytes<INPUT_CAPACITY>);

impl RemainderBytes {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A fixed-capacity chunk of local terminal input, sized like the existing
/// terminal input chunks (capacity [`INPUT_CAPACITY`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInputChunk {
    bytes: [u8; INPUT_CAPACITY],
    len: usize,
}

impl LocalInputChunk {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; INPUT_CAPACITY],
            len: 0,
        }
    }

    /// The writable region of the chunk; fill it and then call
    /// [`Self::set_len`] with the number of bytes actually read.
    #[must_use]
    pub fn writable(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Records how many of the writable bytes are valid input.
    pub fn set_len(&mut self, len: usize) -> Result<(), LocalControlError> {
        if len > INPUT_CAPACITY {
            return Err(LocalControlError::ChunkLengthExceedsCapacity);
        }
        self.len = len;
        Ok(())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Default for LocalInputChunk {
    fn default() -> Self {
        Self::new()
    }
}

/// The outcome of processing one input chunk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessedInput {
    /// Bytes to forward to the remote terminal; empty while modal.
    pub remote_bytes: RemoteBytes,
    /// Ordinary text typed while a modal path prompt is active; handed to the
    /// local path editor.
    pub path_bytes: PathBytes,
    /// Bytes following a recognized `u`/`d` selector in the same chunk; input
    /// for the local file operation, in original order.
    pub remainder: RemainderBytes,
    /// The local action for this chunk.
    pub action: LocalAction,
    /// True exactly when [`Self::remainder`] is non-empty: those bytes belong
    /// exclusively to the newly started local file operation and must be
    /// discarded — never forwarded to the remote — if the operation
    /// terminates before consuming them (peer without support, session
    /// closure, local initialization failure; §6.2).
    pub drop_remainder: bool,
}

/// The local control input state machine (§6.1–§6.4).
///
/// State: pass-through, modal with a prompt or transfer phase, and a terminal
/// ended state reached on [`LocalAction::Detach`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalControlInput {
    enabled: bool,
    ended: bool,
    pending_prefix: bool,
    modal: Option<ModalPhase>,
    transfer_bell_emitted: bool,
}

impl LocalControlInput {
    /// Creates the machine.
    ///
    /// With `enabled = false` the machine is fully transparent (§6.4): no
    /// byte has local semantics, everything is forwarded, and `modal` is
    /// ignored. With `enabled = true, modal = false` the machine starts in
    /// pass-through. With `enabled = true, modal = true` the machine starts
    /// with a file operation already active in the upload prompt phase (the
    /// input semantics of both prompt directions are identical; use
    /// [`Self::with_modal_phase`] to select the direction explicitly).
    #[must_use]
    pub const fn new(enabled: bool, modal: bool) -> Self {
        Self {
            enabled,
            ended: false,
            pending_prefix: false,
            modal: if enabled && modal {
                Some(ModalPhase::UploadPrompt)
            } else {
                None
            },
            transfer_bell_emitted: false,
        }
    }

    /// Creates the machine with an explicit initial modal phase; ignored when
    /// `enabled` is false (§6.4).
    #[must_use]
    pub const fn with_modal_phase(enabled: bool, phase: ModalPhase) -> Self {
        Self {
            enabled,
            ended: false,
            pending_prefix: false,
            modal: if enabled { Some(phase) } else { None },
            transfer_bell_emitted: false,
        }
    }

    /// Whether local control interpretation is enabled (interactive input).
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether the machine has ended after a [`LocalAction::Detach`]; every
    /// further call yields nothing.
    #[must_use]
    pub const fn ended(&self) -> bool {
        self.ended
    }

    /// The phase of the active file operation, if any.
    #[must_use]
    pub const fn modal_phase(&self) -> Option<ModalPhase> {
        self.modal
    }

    /// Whether a `Ctrl+]` prefix is awaiting its selector; the selector may
    /// arrive in the next chunk.
    #[must_use]
    pub const fn pending_prefix(&self) -> bool {
        self.pending_prefix
    }

    /// Processes one bounded input chunk and returns the local outcome.
    ///
    /// Prefix and selector may span chunk boundaries; an empty chunk never
    /// changes the state. When `u` or `d` is recognized, the machine enters
    /// the modal prompt phase and the rest of the chunk becomes the remainder
    /// for the local file operation; when `?` is recognized the rest of the
    /// chunk resumes ordinary forwarding.
    #[must_use]
    pub fn process(&mut self, input: LocalInputChunk) -> ProcessedInput {
        let mut result = ProcessedInput::default();
        if self.ended {
            return result;
        }
        if !self.enabled {
            // §6.4: non-interactive input is fully transparent.
            result.remote_bytes.0.extend(input.as_slice());
            return result;
        }
        match self.modal {
            Some(phase) => self.process_modal(input, phase, &mut result),
            None => self.process_pass_through(input, &mut result),
        }
        result
    }

    /// EOF on the local input stream. An orphaned prefix in pass-through is
    /// flushed as a literal `Ctrl+]` (§6.2); an orphaned prefix in modal is
    /// BEL-ignored (§6.3). Never yields path or remainder bytes.
    #[must_use]
    pub fn finish(&mut self) -> ProcessedInput {
        let mut result = ProcessedInput::default();
        if self.ended || !self.enabled {
            return result;
        }
        if self.pending_prefix {
            self.pending_prefix = false;
            match self.modal {
                Some(_) => result.action = LocalAction::Bell,
                None => result.remote_bytes.0.push(LOCAL_ESCAPE),
            }
        }
        result
    }

    /// Advances an active prompt phase to the transferring phase (§7.5).
    /// Calling it while already transferring is a no-op; calling it with no
    /// active file operation is [`LocalControlError::NoActiveModal`].
    pub fn enter_transfer(&mut self) -> Result<(), LocalControlError> {
        match self.modal {
            Some(ModalPhase::UploadPrompt | ModalPhase::DownloadPrompt) => {
                self.modal = Some(ModalPhase::Transferring);
                self.transfer_bell_emitted = false;
                Ok(())
            }
            Some(ModalPhase::Transferring) => Ok(()),
            None => Err(LocalControlError::NoActiveModal),
        }
    }

    /// Ends the active file operation and returns to pass-through input.
    ///
    /// A `Ctrl+]` prefix abandoned by the transition (no selector arrived
    /// yet) is answered with [`LocalAction::Bell`] and cleared; it never
    /// carries into pass-through, so it cannot detach the session later.
    /// Returns the bell action when a prefix was abandoned, otherwise
    /// [`LocalAction::None`].
    #[must_use]
    pub fn leave_modal(&mut self) -> LocalAction {
        self.modal = None;
        self.transfer_bell_emitted = false;
        if self.pending_prefix {
            self.pending_prefix = false;
            LocalAction::Bell
        } else {
            LocalAction::None
        }
    }

    fn process_pass_through(&mut self, input: LocalInputChunk, result: &mut ProcessedInput) {
        let bytes = input.as_slice();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if self.pending_prefix {
                self.pending_prefix = false;
                match byte {
                    b'.' => {
                        // §6.2: detach ends the session; the rest of the
                        // chunk is moot and the machine ends.
                        result.action = LocalAction::Detach;
                        self.end_session();
                        return;
                    }
                    LOCAL_ESCAPE => {
                        // §6.2: Ctrl+] Ctrl+] sends a literal Ctrl+].
                        result.remote_bytes.0.push(LOCAL_ESCAPE);
                    }
                    b'u' => {
                        result.action = LocalAction::StartUpload;
                        self.enter_prompt(ModalPhase::UploadPrompt);
                        result.remainder.0.extend(&bytes[index + 1..]);
                        result.drop_remainder = !result.remainder.is_empty();
                        return;
                    }
                    b'd' => {
                        result.action = LocalAction::StartDownload;
                        self.enter_prompt(ModalPhase::DownloadPrompt);
                        result.remainder.0.extend(&bytes[index + 1..]);
                        result.drop_remainder = !result.remainder.is_empty();
                        return;
                    }
                    b'?' => {
                        // §6.2: show help; the rest of the chunk resumes
                        // ordinary forwarding.
                        result.action = LocalAction::ShowHelp;
                    }
                    other => {
                        // §6.2: unrecognized selectors (including uppercase
                        // U/D) are forwarded transparently.
                        result.remote_bytes.0.push(LOCAL_ESCAPE);
                        result.remote_bytes.0.push(other);
                    }
                }
            } else if byte == LOCAL_ESCAPE {
                self.pending_prefix = true;
            } else {
                result.remote_bytes.0.push(byte);
            }
            index += 1;
        }
    }

    fn process_modal(&mut self, input: LocalInputChunk, phase: ModalPhase, result: &mut ProcessedInput) {
        for &byte in input.as_slice() {
            if self.pending_prefix {
                self.pending_prefix = false;
                match byte {
                    b'.' => {
                        // §6.3: cancel the operation and end the session.
                        result.action = LocalAction::Detach;
                        self.end_session();
                        return;
                    }
                    b'?' => {
                        // §6.3: show help and stay in the current phase.
                        result.action = LocalAction::ShowHelp;
                    }
                    b'u' | b'd' => {
                        // §6.3: a second operation is refused while active.
                        result.action = LocalAction::AlreadyActive;
                    }
                    _ => {
                        // §6.3: Ctrl+] Ctrl+] and unknown selectors are
                        // BEL-ignored, never forwarded.
                        result.action = LocalAction::Bell;
                    }
                }
            } else if byte == LOCAL_ESCAPE {
                self.pending_prefix = true;
            } else if byte == CANCEL_BYTE {
                // §6.3/§16: Ctrl+C cancels the operation directly, without a
                // prefix, and is never forwarded; the rest of the chunk is
                // dead input for the cancelling operation.
                result.action = LocalAction::CancelOp;
                return;
            } else {
                match phase {
                    ModalPhase::UploadPrompt | ModalPhase::DownloadPrompt => {
                        // §7.4: ordinary bytes (including editor control
                        // bytes) are path editor input.
                        result.path_bytes.0.push(byte);
                    }
                    ModalPhase::Transferring => {
                        // §7.5: paused input is dropped and never replayed;
                        // the first drop rings one local BEL.
                        if !self.transfer_bell_emitted {
                            self.transfer_bell_emitted = true;
                            result.action = LocalAction::Bell;
                        }
                    }
                }
            }
        }
    }

    fn enter_prompt(&mut self, phase: ModalPhase) {
        self.modal = Some(phase);
        self.transfer_bell_emitted = false;
    }

    fn end_session(&mut self) {
        self.ended = true;
        self.modal = None;
        self.pending_prefix = false;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn chunk(bytes: &[u8]) -> LocalInputChunk {
        let mut input = LocalInputChunk::new();
        input.writable()[..bytes.len()].copy_from_slice(bytes);
        input.set_len(bytes.len()).unwrap();
        input
    }

    #[test]
    fn passthrough_is_byte_exact_and_binary_safe() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"hello world"));
        assert_eq!(out.remote_bytes.as_slice(), b"hello world");
        assert_eq!(out.action, LocalAction::None);
        assert!(out.path_bytes.is_empty());
        assert!(out.remainder.is_empty());
        assert!(!out.drop_remainder);
        assert_eq!(machine.modal_phase(), None);

        let binary = [0x00, 0x01, 0x7f, 0xff, 0x0a, 0x1b, 0x1c, 0x1e];
        let out = machine.process(chunk(&binary));
        assert_eq!(out.remote_bytes.as_slice(), &binary);
        assert_eq!(out.action, LocalAction::None);

        // Ctrl+C in pass-through is an ordinary byte and is forwarded.
        let out = machine.process(chunk(b"ab\x03cd"));
        assert_eq!(out.remote_bytes.as_slice(), b"ab\x03cd");

        // An empty chunk is a no-op.
        let out = machine.process(chunk(b""));
        assert!(out.remote_bytes.is_empty());
        assert_eq!(out.action, LocalAction::None);
    }

    #[test]
    fn prefix_dot_detaches_and_ends_the_machine() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1d.abc"));
        assert_eq!(out.action, LocalAction::Detach);
        assert!(out.remote_bytes.is_empty());
        assert!(out.remainder.is_empty());
        assert!(!out.drop_remainder);
        assert!(machine.ended());
        assert_eq!(machine.modal_phase(), None);

        // The machine is terminal: further input yields nothing.
        let out = machine.process(chunk(b"xyz"));
        assert!(out.remote_bytes.is_empty());
        assert_eq!(out.action, LocalAction::None);
        assert!(machine.finish().remote_bytes.is_empty());

        // Modal detach ends the session the same way.
        let mut modal = LocalControlInput::new(true, true);
        let out = modal.process(chunk(b"\x1d.xy"));
        assert_eq!(out.action, LocalAction::Detach);
        assert!(out.remote_bytes.is_empty());
        assert!(out.path_bytes.is_empty());
        assert!(modal.ended());
    }

    #[test]
    fn prefix_double_escape_sends_a_literal_escape() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1d\x1d"));
        assert_eq!(out.remote_bytes.as_slice(), b"\x1d");
        assert_eq!(out.action, LocalAction::None);
        assert_eq!(machine.modal_phase(), None);
        assert!(!machine.pending_prefix());

        // The rest of the chunk is forwarded normally.
        let out = machine.process(chunk(b"\x1d\x1dabc"));
        assert_eq!(out.remote_bytes.as_slice(), b"\x1dabc");
        assert_eq!(out.action, LocalAction::None);

        // Three escapes: one literal plus one pending prefix.
        let out = machine.process(chunk(b"\x1d\x1d\x1d"));
        assert_eq!(out.remote_bytes.as_slice(), b"\x1d");
        assert!(machine.pending_prefix());
    }

    #[test]
    fn prefix_u_starts_upload_and_hands_remainder_to_the_local_operation() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1duabc"));
        assert_eq!(out.action, LocalAction::StartUpload);
        assert!(out.remote_bytes.is_empty());
        assert!(out.path_bytes.is_empty());
        assert_eq!(out.remainder.as_slice(), b"abc");
        assert!(out.drop_remainder);
        assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));

        // The modal context continues across the next chunks.
        let out = machine.process(chunk(b"def"));
        assert_eq!(out.path_bytes.as_slice(), b"def");
        assert!(out.remote_bytes.is_empty());
    }

    #[test]
    fn prefix_d_starts_download_and_hands_remainder() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1ddabc"));
        assert_eq!(out.action, LocalAction::StartDownload);
        assert!(out.remote_bytes.is_empty());
        assert_eq!(out.remainder.as_slice(), b"abc");
        assert!(out.drop_remainder);
        assert_eq!(machine.modal_phase(), Some(ModalPhase::DownloadPrompt));
    }

    #[test]
    fn prefix_u_without_remainder_has_no_drop() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1du"));
        assert_eq!(out.action, LocalAction::StartUpload);
        assert!(out.remainder.is_empty());
        assert!(!out.drop_remainder);
        assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));
    }

    #[test]
    fn prefix_question_shows_help_and_resumes_forwarding() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1d?xy"));
        assert_eq!(out.action, LocalAction::ShowHelp);
        assert_eq!(out.remote_bytes.as_slice(), b"xy");
        assert!(out.remainder.is_empty());
        assert!(!out.drop_remainder);
        assert_eq!(machine.modal_phase(), None);

        // Pass-through continues after the help.
        let out = machine.process(chunk(b"z"));
        assert_eq!(out.remote_bytes.as_slice(), b"z");

        // Help mid-chunk leaves later prefixes intact.
        let out = machine.process(chunk(b"ab\x1d?xy"));
        assert_eq!(out.action, LocalAction::ShowHelp);
        assert_eq!(out.remote_bytes.as_slice(), b"abxy");
    }

    #[test]
    fn uppercase_and_unknown_selectors_are_forwarded_transparently() {
        for selector in [b'U', b'D', b'X', b' ', b'0', 0x00, 0x7f, 0xff, b'\n', b'-'] {
            let mut machine = LocalControlInput::new(true, false);
            let out = machine.process(chunk(&[LOCAL_ESCAPE, selector]));
            assert_eq!(
                out.remote_bytes.as_slice(),
                &[LOCAL_ESCAPE, selector],
                "selector {selector:02x}"
            );
            assert_eq!(out.action, LocalAction::None);
            assert_eq!(machine.modal_phase(), None);
            assert!(!machine.pending_prefix());
        }
    }

    #[test]
    fn prefix_and_selector_span_chunk_boundaries() {
        let cases: &[(&[u8], LocalAction, Option<ModalPhase>)] = &[
            (b".", LocalAction::Detach, None),
            (b"\x1d", LocalAction::None, None),
            (b"u", LocalAction::StartUpload, Some(ModalPhase::UploadPrompt)),
            (
                b"d",
                LocalAction::StartDownload,
                Some(ModalPhase::DownloadPrompt),
            ),
            (b"?", LocalAction::ShowHelp, None),
            (b"U", LocalAction::None, None),
        ];
        for (selector, action, phase) in cases {
            let mut machine = LocalControlInput::new(true, false);
            let first = machine.process(chunk(b"\x1d"));
            assert!(first.remote_bytes.is_empty());
            assert!(machine.pending_prefix());
            let second = machine.process(chunk(selector));
            assert_eq!(second.action, *action, "selector {selector:?}");
            assert_eq!(machine.modal_phase(), *phase, "selector {selector:?}");
            match *selector {
                b"\x1d" => assert_eq!(second.remote_bytes.as_slice(), b"\x1d"),
                b"U" => assert_eq!(second.remote_bytes.as_slice(), b"\x1dU"),
                _ => assert!(second.remote_bytes.is_empty()),
            }
            assert!(second.remainder.is_empty());
            assert!(!second.drop_remainder);
        }
    }

    #[test]
    fn selector_in_a_later_chunk_keeps_remainder_semantics() {
        let mut machine = LocalControlInput::new(true, false);
        let first = machine.process(chunk(b"ab\x1d"));
        assert_eq!(first.remote_bytes.as_slice(), b"ab");
        assert!(machine.pending_prefix());
        let second = machine.process(chunk(b"uabc"));
        assert_eq!(second.action, LocalAction::StartUpload);
        assert!(second.remote_bytes.is_empty());
        assert_eq!(second.remainder.as_slice(), b"abc");
        assert!(second.drop_remainder);
        assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));

        // The modal continues: further input is path input.
        let third = machine.process(chunk(b"def"));
        assert_eq!(third.path_bytes.as_slice(), b"def");
        assert!(third.remote_bytes.is_empty());
    }

    #[test]
    fn empty_chunks_do_not_resolve_a_pending_prefix() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1d"));
        assert!(out.remote_bytes.is_empty());
        let mid = machine.process(chunk(b""));
        assert!(mid.remote_bytes.is_empty());
        assert_eq!(mid.action, LocalAction::None);
        assert!(machine.pending_prefix());
        let second = machine.process(chunk(b"."));
        assert_eq!(second.action, LocalAction::Detach);
    }

    #[test]
    fn remainder_never_replays_to_the_remote() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1duabc"));
        assert_eq!(out.remainder.as_slice(), b"abc");
        assert!(out.drop_remainder);
        assert_eq!(out.action, LocalAction::StartUpload);

        // While the operation is active the remainder never reappears: later
        // chunks are modal input, not a replay of the remainder.
        let next = machine.process(chunk(b"x"));
        assert_eq!(next.path_bytes.as_slice(), b"x");
        assert!(next.remote_bytes.is_empty());
        assert!(next.remainder.is_empty());

        // Simulated termination: the coordinator discards the unconsumed
        // remainder (the drop_remainder path) and leaves the modal state.
        assert_eq!(machine.leave_modal(), LocalAction::None);
        assert_eq!(machine.modal_phase(), None);
        let after = machine.process(chunk(b"abc"));
        assert_eq!(after.remote_bytes.as_slice(), b"abc");
        assert!(!after.drop_remainder);

        // The same drop path with prefix input following the termination.
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"\x1duabc"));
        assert_eq!(out.remainder.as_slice(), b"abc");
        assert_eq!(machine.leave_modal(), LocalAction::None);
        let out = machine.process(chunk(b"\x1dU"));
        assert_eq!(out.remote_bytes.as_slice(), b"\x1dU");
        let out = machine.process(chunk(b"z"));
        assert_eq!(out.remote_bytes.as_slice(), b"z");
    }

    #[test]
    fn drop_remainder_flag_marks_every_remainder() {
        for bytes in [
            b"\x1du".as_slice(),
            b"\x1d".as_slice(),
            b"\x1dux".as_slice(),
            b"\x1d.".as_slice(),
            b"ab".as_slice(),
            b"\x1d?".as_slice(),
            b"\x1ddxyz".as_slice(),
        ] {
            let mut machine = LocalControlInput::new(true, false);
            let out = machine.process(chunk(bytes));
            assert_eq!(
                out.drop_remainder,
                !out.remainder.is_empty(),
                "input {bytes:?}"
            );
        }
    }

    #[test]
    fn modal_prompt_text_becomes_path_input() {
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        let out = machine.process(chunk(b"hello world"));
        assert_eq!(out.path_bytes.as_slice(), b"hello world");
        assert!(out.remote_bytes.is_empty());
        assert_eq!(out.action, LocalAction::None);
        assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));
    }

    #[test]
    fn modal_prompt_passes_editing_control_bytes_to_the_editor() {
        // Only the reserved bytes (Ctrl+], Ctrl+C) are intercepted; editor
        // control bytes (ESC, backspace, DEL, Enter) reach the path editor.
        let mut machine = LocalControlInput::new(true, true);
        let out = machine.process(chunk(&[0x1b, 0x08, 0x7f, b'a', 0x0d]));
        assert_eq!(out.path_bytes.as_slice(), &[0x1b, 0x08, 0x7f, b'a', 0x0d]);
        assert!(out.remote_bytes.is_empty());
    }

    #[test]
    fn modal_prefix_dot_detaches_the_session() {
        let mut machine = LocalControlInput::new(true, true);
        let out = machine.process(chunk(b"\x1d."));
        assert_eq!(out.action, LocalAction::Detach);
        assert!(out.remote_bytes.is_empty());
        assert!(out.path_bytes.is_empty());
        assert!(machine.ended());
    }

    #[test]
    fn modal_prefix_question_keeps_the_modal_phase() {
        let mut machine = LocalControlInput::new(true, true);
        let out = machine.process(chunk(b"\x1d?xy"));
        assert_eq!(out.action, LocalAction::ShowHelp);
        assert_eq!(out.path_bytes.as_slice(), b"xy");
        assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));

        // The selector may arrive in the next chunk.
        let mut machine = LocalControlInput::new(true, true);
        let first = machine.process(chunk(b"\x1d"));
        assert!(first.remote_bytes.is_empty());
        let second = machine.process(chunk(b"?z"));
        assert_eq!(second.action, LocalAction::ShowHelp);
        assert_eq!(second.path_bytes.as_slice(), b"z");
        assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));
    }

    #[test]
    fn modal_repeated_u_or_d_is_already_active() {
        for selector in b"ud" {
            let mut machine = LocalControlInput::new(true, true);
            let out = machine.process(chunk(&[LOCAL_ESCAPE, *selector, b'x']));
            assert_eq!(out.action, LocalAction::AlreadyActive);
            assert!(out.remote_bytes.is_empty());
            assert_eq!(out.path_bytes.as_slice(), b"x");
            assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));
        }
    }

    #[test]
    fn modal_unknown_selectors_and_double_escape_ring_the_bell() {
        for selector in [b'U', b'D', b'X', b' ', 0x00, 0xff, LOCAL_ESCAPE] {
            let mut machine = LocalControlInput::new(true, true);
            let out = machine.process(chunk(&[LOCAL_ESCAPE, selector]));
            assert_eq!(out.action, LocalAction::Bell, "selector {selector:02x}");
            assert!(out.remote_bytes.is_empty());
            assert!(out.path_bytes.is_empty());
            assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));
            // The ignored prefix is not repeated: next input is path input.
            let next = machine.process(chunk(b"z"));
            assert_eq!(next.path_bytes.as_slice(), b"z");
            assert_eq!(next.action, LocalAction::None);
        }
    }

    #[test]
    fn modal_ctrl_c_cancels_without_forwarding() {
        let mut machine = LocalControlInput::new(true, true);
        let out = machine.process(chunk(&[CANCEL_BYTE]));
        assert_eq!(out.action, LocalAction::CancelOp);
        assert!(out.remote_bytes.is_empty());
        assert!(out.path_bytes.is_empty());

        // No prefix is needed; the rest of the chunk is dead input for the
        // cancelling operation and is not processed.
        let out = machine.process(chunk(&[b'a', CANCEL_BYTE, b'b']));
        assert_eq!(out.path_bytes.as_slice(), b"a");
        assert_eq!(out.action, LocalAction::CancelOp);
        assert!(out.remote_bytes.is_empty());

        // Ctrl+C also cancels during the transfer phase.
        let mut transfer = LocalControlInput::new(true, true);
        transfer.enter_transfer().unwrap();
        let out = transfer.process(chunk(&[CANCEL_BYTE]));
        assert_eq!(out.action, LocalAction::CancelOp);
        assert!(out.remote_bytes.is_empty());
        assert!(out.path_bytes.is_empty());
    }

    #[test]
    fn transfer_pauses_ordinary_input_with_a_single_bell() {
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        machine.enter_transfer().unwrap();
        assert_eq!(machine.modal_phase(), Some(ModalPhase::Transferring));

        let first = machine.process(chunk(b"a"));
        assert_eq!(first.action, LocalAction::Bell);
        assert!(first.remote_bytes.is_empty());
        assert!(first.path_bytes.is_empty());

        let second = machine.process(chunk(b"bc"));
        assert_eq!(second.action, LocalAction::None);
        assert!(second.remote_bytes.is_empty());
        assert!(second.path_bytes.is_empty());

        let third = machine.process(chunk(b"d"));
        assert_eq!(third.action, LocalAction::None);
    }

    #[test]
    fn transfer_prefix_selectors_follow_the_modal_rules() {
        let cases: &[(&[u8], LocalAction)] = &[
            (b"\x1d.", LocalAction::Detach),
            (b"\x1d?", LocalAction::ShowHelp),
            (b"\x1du", LocalAction::AlreadyActive),
            (b"\x1dd", LocalAction::AlreadyActive),
            (b"\x1d\x1d", LocalAction::Bell),
            (b"\x1dX", LocalAction::Bell),
        ];
        for (sequence, expected) in cases {
            let mut machine = LocalControlInput::new(true, false);
            let started = machine.process(chunk(b"\x1du"));
            assert_eq!(started.action, LocalAction::StartUpload);
            machine.enter_transfer().unwrap();
            let out = machine.process(chunk(sequence));
            assert_eq!(out.action, *expected, "sequence {sequence:?}");
            assert!(out.remote_bytes.is_empty());
            assert!(out.path_bytes.is_empty());
        }
    }

    #[test]
    fn transfer_prefix_selector_spanning_chunks() {
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        machine.enter_transfer().unwrap();
        let first = machine.process(chunk(b"\x1d"));
        assert_eq!(first.action, LocalAction::None);
        assert!(machine.pending_prefix());
        let second = machine.process(chunk(b"."));
        assert_eq!(second.action, LocalAction::Detach);
        assert!(machine.ended());
    }

    #[test]
    fn eof_flushes_an_orphaned_prefix_in_pass_through() {
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(b"ab\x1d"));
        assert_eq!(out.remote_bytes.as_slice(), b"ab");
        assert!(machine.pending_prefix());
        let eof = machine.finish();
        assert_eq!(eof.remote_bytes.as_slice(), b"\x1d");
        assert_eq!(eof.action, LocalAction::None);
        assert!(!machine.pending_prefix());

        // Clean EOF without a pending prefix produces nothing.
        let mut clean = LocalControlInput::new(true, false);
        assert!(clean.finish().remote_bytes.is_empty());
        assert_eq!(clean.finish().action, LocalAction::None);
    }

    #[test]
    fn eof_bells_an_orphaned_prefix_in_modal() {
        let mut machine = LocalControlInput::new(true, true);
        let out = machine.process(chunk(b"\x1d"));
        assert!(out.remote_bytes.is_empty());
        assert!(machine.pending_prefix());
        let eof = machine.finish();
        assert_eq!(eof.action, LocalAction::Bell);
        assert!(eof.remote_bytes.is_empty());
        assert!(!machine.pending_prefix());

        let mut transfer = LocalControlInput::new(true, true);
        transfer.enter_transfer().unwrap();
        let out = transfer.process(chunk(b"\x1d"));
        assert!(out.remote_bytes.is_empty());
        let eof = transfer.finish();
        assert_eq!(eof.action, LocalAction::Bell);
        assert!(eof.remote_bytes.is_empty());

        // EOF in modal without a pending prefix is silent.
        let mut clean = LocalControlInput::new(true, true);
        assert_eq!(clean.finish().action, LocalAction::None);
    }

    #[test]
    fn disabled_input_is_fully_transparent() {
        for sequence in [
            b"\x1du".as_slice(),
            b"\x1d.".as_slice(),
            b"\x1d\x1d".as_slice(),
            b"\x03".as_slice(),
            b"abc".as_slice(),
            b"\x1d?".as_slice(),
            b"\x1dU".as_slice(),
        ] {
            let mut machine = LocalControlInput::new(false, false);
            let out = machine.process(chunk(sequence));
            assert_eq!(out.remote_bytes.as_slice(), sequence);
            assert_eq!(out.action, LocalAction::None);
            assert!(out.remainder.is_empty());
            assert!(out.path_bytes.is_empty());
            assert!(!out.drop_remainder);
            assert_eq!(machine.modal_phase(), None);
        }
        let mut machine = LocalControlInput::new(false, false);
        assert!(machine.finish().remote_bytes.is_empty());
        assert_eq!(machine.finish().action, LocalAction::None);
        assert!(!machine.pending_prefix());

        // The modal flag is ignored when disabled.
        let mut modal_arg = LocalControlInput::new(false, true);
        assert_eq!(modal_arg.modal_phase(), None);
        let out = modal_arg.process(chunk(b"ab"));
        assert_eq!(out.remote_bytes.as_slice(), b"ab");
        assert_eq!(out.action, LocalAction::None);
    }

    #[test]
    fn leave_modal_returns_to_pass_through() {
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        assert_eq!(machine.leave_modal(), LocalAction::None);
        assert_eq!(machine.modal_phase(), None);
        let out = machine.process(chunk(b"xy"));
        assert_eq!(out.remote_bytes.as_slice(), b"xy");
        assert!(out.path_bytes.is_empty());

        // Leaving without an active operation is a no-op.
        assert_eq!(machine.leave_modal(), LocalAction::None);
    }

    #[test]
    fn leave_modal_bells_an_abandoned_prefix() {
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        let pending = machine.process(chunk(b"\x1d"));
        assert!(pending.remote_bytes.is_empty());
        assert!(machine.pending_prefix());
        assert_eq!(machine.leave_modal(), LocalAction::Bell);
        assert!(!machine.pending_prefix());
        assert_eq!(machine.modal_phase(), None);

        // The abandoned prefix must not detach later input.
        let out = machine.process(chunk(b"."));
        assert_eq!(out.remote_bytes.as_slice(), b".");
        assert_eq!(out.action, LocalAction::None);
    }

    #[test]
    fn enter_transfer_requires_an_active_prompt() {
        let mut machine = LocalControlInput::new(true, false);
        assert_eq!(machine.enter_transfer(), Err(LocalControlError::NoActiveModal));

        let started = machine.process(chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        assert_eq!(machine.enter_transfer(), Ok(()));
        assert_eq!(machine.modal_phase(), Some(ModalPhase::Transferring));
        assert_eq!(machine.enter_transfer(), Ok(())); // idempotent

        assert_eq!(machine.leave_modal(), LocalAction::None);
        assert_eq!(machine.enter_transfer(), Err(LocalControlError::NoActiveModal));

        let mut download = LocalControlInput::new(true, false);
        let started = download.process(chunk(b"\x1dd"));
        assert_eq!(started.action, LocalAction::StartDownload);
        download.enter_transfer().unwrap();
        assert_eq!(download.modal_phase(), Some(ModalPhase::Transferring));

        // A fresh transfer gets a fresh single bell.
        let mut fresh = LocalControlInput::new(true, false);
        let started = fresh.process(chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        fresh.enter_transfer().unwrap();
        assert_eq!(fresh.process(chunk(b"x")).action, LocalAction::Bell);
        assert_eq!(fresh.leave_modal(), LocalAction::None);
        let restarted = fresh.process(chunk(b"\x1du"));
        assert_eq!(restarted.action, LocalAction::StartUpload);
        fresh.enter_transfer().unwrap();
        assert_eq!(fresh.process(chunk(b"x")).action, LocalAction::Bell);
    }

    #[test]
    fn constructed_modal_machines_start_in_the_prompt_phase() {
        let mut machine = LocalControlInput::new(true, true);
        assert_eq!(machine.modal_phase(), Some(ModalPhase::UploadPrompt));
        let out = machine.process(chunk(b"abc"));
        assert_eq!(out.path_bytes.as_slice(), b"abc");
        assert!(out.remote_bytes.is_empty());
        let out = machine.process(chunk(&[CANCEL_BYTE]));
        assert_eq!(out.action, LocalAction::CancelOp);
    }

    #[test]
    fn explicit_modal_phase_constructor() {
        let mut machine = LocalControlInput::with_modal_phase(true, ModalPhase::DownloadPrompt);
        let out = machine.process(chunk(b"x"));
        assert_eq!(out.path_bytes.as_slice(), b"x");
        assert_eq!(machine.modal_phase(), Some(ModalPhase::DownloadPrompt));
        let out = machine.process(chunk(b"\x1dd"));
        assert_eq!(out.action, LocalAction::AlreadyActive);

        // Disabled machines never report a modal phase.
        let disabled = LocalControlInput::with_modal_phase(false, ModalPhase::Transferring);
        assert_eq!(disabled.modal_phase(), None);
    }

    #[test]
    fn chunk_length_is_bounded() {
        let mut input = LocalInputChunk::new();
        assert_eq!(input.writable().len(), INPUT_CAPACITY);
        assert!(input.set_len(INPUT_CAPACITY + 1).is_err());
        assert!(input.set_len(usize::MAX).is_err());
        assert!(input.set_len(INPUT_CAPACITY).is_ok());
        assert_eq!(input.as_slice().len(), INPUT_CAPACITY);
        assert!(input.set_len(0).is_ok());
        assert!(input.as_slice().is_empty());
    }

    #[test]
    fn outputs_never_exceed_their_fixed_capacity() {
        // A full chunk of ordinary bytes is forwarded exactly.
        let ordinary = vec![b'a'; INPUT_CAPACITY];
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(&ordinary));
        assert_eq!(out.remote_bytes.as_slice(), ordinary.as_slice());

        // A carried prefix plus a full chunk is the worst case for remote
        // output: exactly REMOTE_CAPACITY bytes.
        let escapes = vec![LOCAL_ESCAPE; INPUT_CAPACITY - 1];
        let mut machine = LocalControlInput::new(true, false);
        let first = machine.process(chunk(&escapes));
        assert_eq!(first.remote_bytes.len(), INPUT_CAPACITY / 2 - 1);
        assert!(machine.pending_prefix());
        let second = machine.process(chunk(&ordinary));
        assert_eq!(second.remote_bytes.len(), REMOTE_CAPACITY);
        assert_eq!(second.remote_bytes.as_slice()[0], LOCAL_ESCAPE);
        assert_eq!(second.remote_bytes.as_slice()[1], b'a');

        // A full modal chunk becomes path input, never remote bytes.
        let mut machine = LocalControlInput::new(true, true);
        let out = machine.process(chunk(&ordinary));
        assert_eq!(out.path_bytes.len(), INPUT_CAPACITY);
        assert!(out.remote_bytes.is_empty());

        // The maximum remainder is the chunk minus prefix and selector.
        let mut block = vec![LOCAL_ESCAPE, b'u'];
        block.extend(std::iter::repeat_n(b'x', INPUT_CAPACITY - 2));
        let mut machine = LocalControlInput::new(true, false);
        let out = machine.process(chunk(&block));
        assert_eq!(out.remainder.len(), INPUT_CAPACITY - 2);
        assert!(out.drop_remainder);
    }

    #[test]
    fn every_prefix_selector_sequence_is_split_invariant() {
        let sequences: &[&[u8]] = &[
            b"\x1d.xy",
            b"\x1d\x1dz",
            b"\x1duabc",
            b"\x1ddabc",
            b"\x1d?xy",
            b"\x1dUxy",
        ];
        for sequence in sequences {
            let mut reference = LocalControlInput::new(true, false);
            let expected = reference.process(chunk(sequence));
            let expected_phase = reference.modal_phase();
            for split in 1..sequence.len() {
                let mut machine = LocalControlInput::new(true, false);
                let mut remote = Vec::new();
                let mut op_input = Vec::new();
                let mut action = LocalAction::None;
                let first = machine.process(chunk(&sequence[..split]));
                remote.extend_from_slice(first.remote_bytes.as_slice());
                op_input.extend_from_slice(first.remainder.as_slice());
                if first.action != LocalAction::None {
                    action = first.action;
                }
                let second = machine.process(chunk(&sequence[split..]));
                remote.extend_from_slice(second.remote_bytes.as_slice());
                op_input.extend_from_slice(second.remainder.as_slice());
                op_input.extend_from_slice(second.path_bytes.as_slice());
                if second.action != LocalAction::None {
                    action = second.action;
                }
                assert_eq!(remote, expected.remote_bytes.as_slice(), "{sequence:?} split {split}");
                assert_eq!(op_input, expected.remainder.as_slice(), "{sequence:?} split {split}");
                assert_eq!(action, expected.action, "{sequence:?} split {split}");
                assert_eq!(machine.modal_phase(), expected_phase, "{sequence:?} split {split}");
            }
        }
    }

    #[test]
    fn arbitrary_byte_sequences_never_panic_and_stay_bounded() {
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        for _ in 0..2000 {
            let mode = next() % 4;
            let mut machine = match mode {
                0 => LocalControlInput::new(true, false),
                1 => LocalControlInput::new(true, true),
                2 => LocalControlInput::new(false, false),
                _ => {
                    let mut machine = LocalControlInput::new(true, false);
                    let _ = machine.process(chunk(b"\x1du"));
                    machine
                }
            };
            if mode == 3 {
                machine.enter_transfer().unwrap();
            }
            let block_len = usize::from(next() % 64);
            let block: Vec<u8> = (0..block_len).map(|_| next()).collect();
            let was_modal = machine.modal_phase().is_some();
            let out = machine.process(chunk(&block));
            assert!(out.remote_bytes.len() <= REMOTE_CAPACITY);
            assert!(out.path_bytes.len() <= INPUT_CAPACITY);
            assert!(out.remainder.len() <= INPUT_CAPACITY);
            assert_eq!(out.drop_remainder, !out.remainder.is_empty());
            if was_modal {
                // A block processed while already modal never emits remote
                // bytes; the block that enters modal may forward the bytes
                // before its u/d selector.
                assert!(out.remote_bytes.is_empty());
            }
            let eof = machine.finish();
            assert!(eof.remote_bytes.len() <= REMOTE_CAPACITY);
            assert!(eof.remainder.is_empty());
            assert!(eof.path_bytes.is_empty());
            let _ = machine.leave_modal();
        }
    }

    #[test]
    fn errors_are_structured_and_displayable() {
        let capacity = LocalControlError::ChunkLengthExceedsCapacity;
        assert!(capacity.to_string().contains("capacity"));
        let no_modal = LocalControlError::NoActiveModal;
        assert!(no_modal.to_string().contains("file operation"));
        assert_ne!(capacity, no_modal);
        let _: &dyn std::error::Error = &capacity;
        let _: &dyn std::error::Error = &no_modal;
    }
}
