//! Controller-side path prompt and delayed remote-output buffer for the
//! 0.2.0 native file transfer flow.
//!
//! Implements the frozen design sections §6.2/§6.3 (input routing), §7.2 and
//! §7.3 (upload and download prompts), §7.4 (prompt-time terminal handling),
//! §8.5 (path encoding), §15.1 (bounded memory), §16.1 (prompt-stage
//! cancellation) and the §23.2 required test matrix.
//!
//! The prompt is pure controller-local UI state: it never writes to
//! terminal-data, never logs, performs no I/O and no async, and never parses
//! or normalizes a path. Paths are collected as literal bytes — local
//! relative paths stay relative to the local base directory, remote paths
//! are interpreted only by the peer's operating system, spaces are ordinary
//! characters and no shell expansion ever happens.
//!
//! The delayed output buffer holds remote terminal output that the
//! controller keeps reading but does not display while the prompt is active.
//! Its capacity is a hard per-session bound (256 KiB in production); an
//! overflow never drops already-buffered bytes and never closes the remote
//! terminal.

use std::str::from_utf8;
use yonder_core::wire::file_transfer::{MAX_PATH_LEN, validate_protocol_path};

/// Production path limit in UTF-8 bytes (design §8.5).
pub const PROMPT_PATH_LIMIT: usize = MAX_PATH_LEN;

/// Production per-session delayed-output cap for the path prompt (design
/// §7.4, §15.1): exactly 256 KiB = 262144 bytes.
pub const DELAYED_OUTPUT_CAP: usize = 256 * 1024;

/// The outcome of one [`PathPrompt::feed`] or [`PathPrompt::feed_initial`]
/// call.
///
/// The variants form two classes:
///
/// - Terminal outcomes — [`PromptResult::Submitted`],
///   [`PromptResult::Empty`], [`PromptResult::Cancelled`] and
///   [`PromptResult::Reprompt`] — end the prompt. Bytes that follow a
///   terminal outcome within the same feed call are dropped: per design
///   §6.2 they belong to the local file operation and must never be
///   forwarded to the remote PTY.
/// - [`PromptResult::Bell`] and [`PromptResult::Continue`] keep the prompt
///   active. If one feed produces both a bell event and a terminal event,
///   the terminal outcome wins.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum PromptResult {
    /// A valid protocol path was submitted and is ready for use.
    Submitted(Box<str>),
    /// An optional destination field was submitted empty: the caller uses
    /// the default target directory. Never produced when the prompt was
    /// created with `allow_empty = false`.
    Empty,
    /// `Ctrl+C` cancelled the operation during the prompt (design §16.1):
    /// no file substream is opened and nothing is sent to the remote PTY.
    Cancelled,
    /// The accumulated input is invalid — an empty required field, an
    /// over-long line, or a line that is not a valid protocol path
    /// (design §8.5). The accumulated line has been discarded; the caller
    /// must re-prompt.
    Reprompt,
    /// At least one byte was rejected (control character, invalid UTF-8, or
    /// a continuation byte without an open sequence). The byte was ignored;
    /// the caller should ring the terminal bell and keep prompting.
    Bell,
    /// Nothing happened; keep feeding bytes.
    Continue,
}

/// A single-line interactive path prompt for the controller-side upload and
/// download flows (design §7.2, §7.3, §8.5).
///
/// Byte handling:
///
/// - `Ctrl+C` (0x03) cancels the operation and never enters the field;
/// - backspace (0x08 or 0x7f) removes the most recently typed input;
/// - `\n`, `\r` and `\r\n` submit — the trailing `\n` of a `\r\n` pair is
///   consumed as part of the same submit event because processing stops at
///   the first terminal outcome;
/// - printable UTF-8 bytes are appended; a multi-byte sequence may span
///   feed calls and is buffered until complete, so a half sequence is never
///   added to the field;
/// - any other control byte, an invalid UTF-8 byte, or a continuation byte
///   without an open sequence produces a bell event and is ignored.
///
/// The line is bounded: appending a character that would push the encoded
/// length past `max_len` returns [`PromptResult::Reprompt`] and discards
/// the line. Submission additionally validates the protocol path rules of
/// §8.5 (UTF-8, no NUL, C0/C1 controls or DEL, at most 4096 bytes) with
/// `yonder_core`'s [`validate_protocol_path`]; this catches characters such
/// as U+0080-U+009F which are valid UTF-8 but forbidden in a path.
#[derive(Debug)]
pub struct PathPrompt {
    /// Input-time line bound in UTF-8 bytes.
    max_len: usize,
    /// Whether an empty submit means "use the default target" (`Empty`)
    /// instead of an invalid input (`Reprompt`).
    allow_empty: bool,
    /// Complete characters typed so far; always valid UTF-8 by construction.
    line: String,
    /// Incomplete multi-byte sequence (lead byte plus continuation bytes);
    /// at most 3 bytes are ever held.
    pending: [u8; 3],
    pending_len: usize,
    /// Total length of the sequence currently being assembled.
    pending_expected: usize,
}

impl PathPrompt {
    /// Creates a prompt with the given input-time line bound in UTF-8 bytes
    /// and the empty-submit policy.
    ///
    /// Production code passes [`PROMPT_PATH_LIMIT`]. `allow_empty = false`
    /// for the required fields (`local source` / `remote source`);
    /// `allow_empty = true` for the defaultable destination fields. Passing
    /// `max_len` above [`PROMPT_PATH_LIMIT`] only widens the input window:
    /// submission still rejects anything the protocol cannot carry.
    #[must_use]
    pub fn new(max_len: usize, allow_empty: bool) -> Self {
        Self {
            max_len,
            allow_empty,
            line: String::new(),
            pending: [0; 3],
            pending_len: 0,
            pending_expected: 0,
        }
    }

    /// Convenience constructor for a required field: an empty submit is an
    /// error.
    #[must_use]
    pub fn required(max_len: usize) -> Self {
        Self::new(max_len, false)
    }

    /// Convenience constructor for a defaultable destination field: an empty
    /// submit means "default target directory".
    #[must_use]
    pub fn with_default(max_len: usize) -> Self {
        Self::new(max_len, true)
    }

    /// Feeds the initial remainder of the read block that contained the
    /// `Ctrl+] u` / `Ctrl+] d` selector (design §6.2). The bytes are
    /// appended to the current line in their original order, never dropped.
    /// Semantics are identical to [`PathPrompt::feed`]; the distinct entry
    /// point lets the input adapter name the two call sites.
    pub fn feed_initial(&mut self, bytes: &[u8]) -> PromptResult {
        self.feed_impl(bytes)
    }

    /// Feeds subsequent input bytes.
    ///
    /// Bytes are processed in order until the first terminal outcome
    /// ([`PromptResult::Submitted`], [`PromptResult::Empty`],
    /// [`PromptResult::Cancelled`] or [`PromptResult::Reprompt`]); any bytes
    /// after it within this call are dropped. Otherwise the result is
    /// [`PromptResult::Bell`] if any byte was rejected, else
    /// [`PromptResult::Continue`].
    pub fn feed(&mut self, bytes: &[u8]) -> PromptResult {
        self.feed_impl(bytes)
    }

    /// The complete line accumulated so far. Incomplete trailing UTF-8
    /// sequences are not part of the line.
    #[must_use]
    pub fn current_line(&self) -> &str {
        &self.line
    }

    /// Discards the accumulated input and pending state; used when
    /// re-prompting.
    pub fn clear(&mut self) {
        self.reset();
    }

    fn feed_impl(&mut self, bytes: &[u8]) -> PromptResult {
        let mut bell = false;
        for &byte in bytes {
            match self.step(byte) {
                StepOutcome::Terminal(result) => return result,
                StepOutcome::Bell => bell = true,
                StepOutcome::Continue => {}
            }
        }
        if bell {
            PromptResult::Bell
        } else {
            PromptResult::Continue
        }
    }

    fn step(&mut self, byte: u8) -> StepOutcome {
        match byte {
            0x03 => {
                self.reset();
                StepOutcome::Terminal(PromptResult::Cancelled)
            }
            b'\n' | b'\r' => StepOutcome::Terminal(self.submit()),
            0x08 | 0x7f => {
                self.backspace();
                StepOutcome::Continue
            }
            0x20..=0x7e => self.append_ascii(byte),
            0x80..=0xbf => self.continue_sequence(byte),
            0xc2..=0xf4 => self.start_sequence(byte),
            // Remaining C0 controls (0x1d included: the `Ctrl+]` prefix is
            // resolved by the input state machine and is a control character
            // here), invalid UTF-8 lead bytes 0xc0/0xc1/0xf5-0xff.
            _ => StepOutcome::Bell,
        }
    }

    fn append_ascii(&mut self, byte: u8) -> StepOutcome {
        if self.line.len() >= self.max_len {
            return self.reprompt();
        }
        self.line.push(char::from(byte));
        StepOutcome::Continue
    }

    fn start_sequence(&mut self, lead: u8) -> StepOutcome {
        let mut outcome = StepOutcome::Continue;
        if self.pending_len != 0 {
            // A truncated previous sequence is discarded: it never entered
            // the line.
            outcome = StepOutcome::Bell;
        }
        self.pending[0] = lead;
        self.pending_len = 1;
        self.pending_expected = sequence_len(lead);
        outcome
    }

    fn continue_sequence(&mut self, byte: u8) -> StepOutcome {
        if self.pending_len == 0 || self.pending_len >= self.pending_expected {
            // A continuation byte without an open sequence is invalid input.
            return StepOutcome::Bell;
        }
        if self.pending_len + 1 < self.pending_expected {
            self.pending[self.pending_len] = byte;
            self.pending_len += 1;
            return StepOutcome::Continue;
        }
        // This byte completes the sequence; validate it strictly, which
        // rejects overlong and surrogate encodings.
        let mut seq = [0_u8; 4];
        let seq_len = self.pending_len + 1;
        seq[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        seq[self.pending_len] = byte;
        self.pending_len = 0;
        let Ok(text) = from_utf8(&seq[..seq_len]) else {
            return StepOutcome::Bell;
        };
        if self.line.len() + seq_len > self.max_len {
            return self.reprompt();
        }
        self.line.push_str(text);
        StepOutcome::Continue
    }

    fn backspace(&mut self) {
        if self.pending_len != 0 {
            // The most recent input is the incomplete sequence; drop it.
            self.pending_len = 0;
            return;
        }
        // `String::pop` removes exactly one Unicode scalar value.
        self.line.pop();
    }

    fn submit(&mut self) -> PromptResult {
        // An incomplete trailing sequence never becomes part of the field.
        self.pending_len = 0;
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            return if self.allow_empty {
                PromptResult::Empty
            } else {
                PromptResult::Reprompt
            };
        }
        if validate_protocol_path(line.as_bytes()).is_err() {
            return PromptResult::Reprompt;
        }
        PromptResult::Submitted(line.into_boxed_str())
    }

    fn reprompt(&mut self) -> StepOutcome {
        self.reset();
        StepOutcome::Terminal(PromptResult::Reprompt)
    }

    fn reset(&mut self) {
        self.line.clear();
        self.pending_len = 0;
    }
}

/// Expected total length of the sequence started by a valid UTF-8 lead byte
/// (only called with `0xc2..=0xf4`).
fn sequence_len(lead: u8) -> usize {
    match lead {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

enum StepOutcome {
    Terminal(PromptResult),
    Bell,
    Continue,
}

/// The outcome of a [`DelayedOutputBuffer::append`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum AppendOutcome {
    /// The bytes were accepted into the buffer.
    Ok,
    /// The bytes were rejected because they would exceed the capacity; they
    /// were not written and the already-buffered bytes are untouched. The
    /// caller must cancel the not-yet-started file operation, restore the
    /// terminal and flush the buffer immediately (design §7.4).
    Overflow,
}

/// Bounded FIFO buffer for remote terminal output that is read but not
/// displayed while a local path prompt is active (design §7.4, §15.1).
///
/// Bytes are preserved in append order and the capacity is a hard
/// per-session bound — 256 KiB in production ([`DELAYED_OUTPUT_CAP`]),
/// smaller in tests. An overflow never drops already-buffered bytes and
/// never affects the remote terminal: the buffer reports
/// [`AppendOutcome::Overflow`] and stays fully readable.
#[derive(Debug)]
pub struct DelayedOutputBuffer {
    capacity: usize,
    bytes: Vec<u8>,
}

impl DelayedOutputBuffer {
    /// Creates an empty buffer with the given hard capacity in bytes.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            bytes: Vec::new(),
        }
    }

    /// The configured hard capacity in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Appends bytes at the tail. Returns [`AppendOutcome::Overflow`] — and
    /// writes nothing — when the buffer would grow beyond the capacity.
    pub fn append(&mut self, bytes: &[u8]) -> AppendOutcome {
        let Some(total) = self.bytes.len().checked_add(bytes.len()) else {
            return AppendOutcome::Overflow;
        };
        if total > self.capacity {
            return AppendOutcome::Overflow;
        }
        self.bytes.extend_from_slice(bytes);
        AppendOutcome::Ok
    }

    /// Takes all delayed bytes in append order and empties the buffer. The
    /// copy is bounded by the capacity.
    #[must_use]
    pub fn take_all(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }

    /// Whether no bytes are currently buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The number of buffered bytes.
    #[must_use]
    pub fn used(&self) -> usize {
        self.bytes.len()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn plain_path_submits() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"abc"), PromptResult::Continue);
        assert_eq!(prompt.current_line(), "abc");
        assert_eq!(
            prompt.feed(b"d\r\n"),
            PromptResult::Submitted("abcd".into())
        );
        assert_eq!(prompt.current_line(), "");
    }

    #[test]
    fn empty_required_path_reprompts() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\n"), PromptResult::Reprompt);
        assert_eq!(prompt.feed(b"\r\n"), PromptResult::Reprompt);
        assert_eq!(prompt.feed(b"\r"), PromptResult::Reprompt);
    }

    #[test]
    fn reprompt_leaves_a_fresh_prompt() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\n"), PromptResult::Reprompt);
        assert_eq!(prompt.current_line(), "");
        assert_eq!(prompt.feed(b"ok\r\n"), PromptResult::Submitted("ok".into()));
    }

    #[test]
    fn empty_optional_destination_returns_empty() {
        let mut prompt = PathPrompt::with_default(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\r\n"), PromptResult::Empty);
        assert_eq!(prompt.feed(b"\n"), PromptResult::Empty);
        assert_eq!(
            prompt.feed(b"target\r\n"),
            PromptResult::Submitted("target".into())
        );
    }

    #[test]
    fn spaces_are_ordinary_path_characters() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"  a  b \r\n"),
            PromptResult::Submitted("  a  b ".into())
        );
    }

    #[test]
    fn unicode_path_round_trips() {
        // Latin-1 supplement, CJK and a four-byte supplementary character.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed("üñï/中漢頭/é𠠠\n".as_bytes()),
            PromptResult::Submitted("üñï/中漢頭/é𠠠".into())
        );
    }

    #[test]
    fn utf8_sequences_may_split_across_feed_calls() {
        // Two-byte character split 1 + 1.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(&[0xc3]), PromptResult::Continue);
        assert_eq!(prompt.current_line(), "");
        assert_eq!(prompt.feed(&[0xa9]), PromptResult::Continue);
        assert_eq!(prompt.current_line(), "é");

        // Three-byte character split 1 + 2 and 2 + 1.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed("中".as_bytes().split_at(1).0),
            PromptResult::Continue
        );
        assert_eq!(
            prompt.feed("中".as_bytes().split_at(1).1),
            PromptResult::Continue
        );
        assert_eq!(prompt.current_line(), "中");
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        let (first, rest) = "中".as_bytes().split_at(2);
        assert_eq!(prompt.feed(first), PromptResult::Continue);
        assert_eq!(prompt.feed(rest), PromptResult::Continue);
        assert_eq!(prompt.current_line(), "中");

        // Four-byte character split 1 + 1 + 1 + 1.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        for part in "𠠠".as_bytes() {
            assert_eq!(prompt.feed(&[*part]), PromptResult::Continue);
        }
        assert_eq!(prompt.current_line(), "𠠠");
        assert_eq!(prompt.feed(b"\n"), PromptResult::Submitted("𠠠".into()));
    }

    #[test]
    fn utf8_sequence_split_inside_a_larger_line() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"ab\xc3"), PromptResult::Continue);
        assert_eq!(prompt.current_line(), "ab");
        assert_eq!(
            prompt.feed(b"\xa9cd\r\n"),
            PromptResult::Submitted("abécd".into())
        );
    }

    #[test]
    fn incomplete_trailing_sequence_is_not_submitted() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"ab\xc3\n"),
            PromptResult::Submitted("ab".into())
        );
    }

    #[test]
    fn over_long_input_reprompts_and_discards_the_line() {
        let mut prompt = PathPrompt::new(8, false);
        assert_eq!(prompt.feed(b"12345678"), PromptResult::Continue);
        assert_eq!(prompt.feed(b"9"), PromptResult::Reprompt);
        assert_eq!(prompt.current_line(), "");
    }

    #[test]
    fn protocol_limit_is_enforced_while_typing() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        let at_limit = vec![b'a'; PROMPT_PATH_LIMIT];
        assert_eq!(prompt.feed(&at_limit), PromptResult::Continue);
        assert_eq!(prompt.current_line().len(), PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"a"), PromptResult::Reprompt);
    }

    #[test]
    fn exactly_max_len_submits() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        let mut at_limit = vec![b'a'; PROMPT_PATH_LIMIT];
        at_limit.push(b'\n');
        match prompt.feed(&at_limit) {
            PromptResult::Submitted(path) => assert_eq!(path.len(), PROMPT_PATH_LIMIT),
            other => panic!("expected Submitted, got {other:?}"),
        }
    }

    #[test]
    fn over_max_len_rejects_even_short_unicode_remainders() {
        // max_len counts encoded bytes, so a 4-byte character overflows a
        // 3-byte budget even though no partial bytes were ever appended.
        let mut prompt = PathPrompt::new(3, false);
        assert_eq!(prompt.feed("𠠠".as_bytes()), PromptResult::Reprompt);
    }

    #[test]
    fn ctrl_c_cancels_alone_or_embedded() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\x03"), PromptResult::Cancelled);
        assert_eq!(prompt.current_line(), "");

        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"abc\x03"), PromptResult::Cancelled);
        assert_eq!(prompt.current_line(), "");

        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\x03def"), PromptResult::Cancelled);

        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"abc"), PromptResult::Continue);
        assert_eq!(prompt.feed(b"\x03"), PromptResult::Cancelled);
    }

    #[test]
    fn control_bytes_bell_and_are_ignored() {
        for byte in [
            0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0b, 0x0c, 0x0e, 0x1d, 0x1f,
        ] {
            let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
            assert_eq!(prompt.feed(&[byte]), PromptResult::Bell, "byte {byte:#04x}");
            assert_eq!(prompt.current_line(), "");
        }
        // Interleaved with valid input the illegal byte is skipped.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"ab\x01cd\x1d\r\n"),
            PromptResult::Submitted("abcd".into())
        );
    }

    #[test]
    fn bell_is_reported_when_no_terminal_event_happens() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\x01"), PromptResult::Bell);
        assert_eq!(prompt.feed(b"\x01\x02"), PromptResult::Bell);
        assert_eq!(prompt.feed(b"a\x01b"), PromptResult::Bell);
        assert_eq!(prompt.current_line(), "ab");
    }

    #[test]
    fn terminal_event_wins_over_bell_in_the_same_feed() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"\x01abc\n"),
            PromptResult::Submitted("abc".into())
        );
    }

    #[test]
    fn crlf_and_bare_newline_submit() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"one\r\n"),
            PromptResult::Submitted("one".into())
        );
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"two\n"), PromptResult::Submitted("two".into()));
        // A bare CR submits immediately; the following LF of the pair is
        // consumed as part of the same event.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"three\r"),
            PromptResult::Submitted("three".into())
        );
        assert_eq!(prompt.feed(b"\n"), PromptResult::Reprompt);
    }

    #[test]
    fn backspace_deletes_the_last_character() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"abc\x7f\r\n"),
            PromptResult::Submitted("ab".into())
        );
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"abc\x08d\r\n"),
            PromptResult::Submitted("abd".into())
        );
        // Backspace removes a full Unicode scalar value, not one byte.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed("a𠠠b\x7f\n".as_bytes()),
            PromptResult::Submitted("a𠠠".into())
        );
        // Backspace on an empty line is a no-op.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\x7f\x7f\n"), PromptResult::Reprompt);
    }

    #[test]
    fn backspace_drops_the_incomplete_utf8_sequence() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"a\xc3\x7f"), PromptResult::Continue);
        assert_eq!(prompt.current_line(), "a");
        // The dropped lead byte is gone: this continuation is now orphaned.
        assert_eq!(prompt.feed(b"\x80"), PromptResult::Bell);
        assert_eq!(prompt.feed(b"b\n"), PromptResult::Submitted("ab".into()));
    }

    #[test]
    fn invalid_utf8_bytes_bell_and_are_ignored() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"a\xffb\r\n"),
            PromptResult::Submitted("ab".into())
        );
        // Invalid lead bytes.
        for byte in [0xc0, 0xc1, 0xf5, 0xff] {
            let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
            assert_eq!(prompt.feed(&[byte]), PromptResult::Bell, "byte {byte:#04x}");
        }
        // A lone continuation byte.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"\x80"), PromptResult::Bell);
        // A truncated sequence is dropped when a new lead byte arrives, and
        // the new sequence still completes.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed(b"\xc3\xc3\xa9\n"),
            PromptResult::Submitted("é".into())
        );
    }

    #[test]
    fn submitted_path_with_c1_control_reprompts() {
        // U+0080-U+009F are valid UTF-8 so they pass the input filter, but
        // the protocol path rules of §8.5 forbid C1 controls.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed("a\u{80}b\n".as_bytes()), PromptResult::Reprompt);
        assert_eq!(prompt.current_line(), "");
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed("c\u{9f}\n".as_bytes()), PromptResult::Reprompt);
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed("\u{80}\n".as_bytes()), PromptResult::Reprompt);
    }

    #[test]
    fn feed_initial_prefills_the_line() {
        // The selector block remainder (design §6.2) is appended in order.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed_initial(b"src/file"), PromptResult::Continue);
        assert_eq!(prompt.current_line(), "src/file");
        assert_eq!(
            prompt.feed(b".txt\n"),
            PromptResult::Submitted("src/file.txt".into())
        );
        // feed_initial can also complete a prompt on its own.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(
            prompt.feed_initial(b"src/file\n"),
            PromptResult::Submitted("src/file".into())
        );
        // Cancellation works through the initial entry point too.
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed_initial(b"abc\x03"), PromptResult::Cancelled);
    }

    #[test]
    fn clear_resets_for_a_reprompt() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"abc"), PromptResult::Continue);
        prompt.clear();
        assert_eq!(prompt.current_line(), "");
        assert_eq!(prompt.feed(b"\n"), PromptResult::Reprompt);
    }

    #[test]
    fn prompt_is_reusable_after_a_terminal_outcome() {
        let mut prompt = PathPrompt::required(PROMPT_PATH_LIMIT);
        assert_eq!(prompt.feed(b"one\n"), PromptResult::Submitted("one".into()));
        assert_eq!(prompt.feed(b"two\n"), PromptResult::Submitted("two".into()));
    }

    #[test]
    fn line_stays_under_the_bound_after_backspace() {
        let mut prompt = PathPrompt::new(4, false);
        assert_eq!(prompt.feed(b"abcd"), PromptResult::Continue);
        assert_eq!(
            prompt.feed(b"\x7fe\n"),
            PromptResult::Submitted("abce".into())
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// Arbitrary byte streams — including adversarial control bytes and
        /// truncated UTF-8 — must never panic and must keep the line within
        /// its invariants: valid UTF-8, free of C0 controls and DEL, bounded
        /// by the configured limit.
        #[test]
        fn arbitrary_input_keeps_prompt_invariants(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..64),
        ) {
            let mut prompt = PathPrompt::new(PROMPT_PATH_LIMIT, false);
            for chunk in &chunks {
                let _ = prompt.feed(chunk);
                let line = prompt.current_line();
                prop_assert!(line.len() <= PROMPT_PATH_LIMIT);
                prop_assert!(from_utf8(line.as_bytes()).is_ok());
                prop_assert!(!line.bytes().any(|b| b <= 0x1f || b == 0x7f));
            }
        }
    }

    #[test]
    fn delayed_output_preserves_append_order() {
        let mut buffer = DelayedOutputBuffer::new(16);
        assert_eq!(buffer.append(b"a"), AppendOutcome::Ok);
        assert_eq!(buffer.append(b"bc"), AppendOutcome::Ok);
        assert_eq!(buffer.append(b"def"), AppendOutcome::Ok);
        assert_eq!(buffer.used(), 6);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.capacity(), 16);
        assert_eq!(buffer.take_all(), b"abcdef".to_vec());
        assert!(buffer.is_empty());
        assert_eq!(buffer.used(), 0);
        assert_eq!(buffer.take_all(), Vec::<u8>::new());
    }

    #[test]
    fn empty_buffer_take_all_is_empty() {
        let mut buffer = DelayedOutputBuffer::new(8);
        assert!(buffer.is_empty());
        assert_eq!(buffer.used(), 0);
        assert_eq!(buffer.take_all(), Vec::<u8>::new());
    }

    #[test]
    fn exact_capacity_fit_is_ok() {
        let mut buffer = DelayedOutputBuffer::new(10);
        assert_eq!(buffer.append(b"0123456789"), AppendOutcome::Ok);
        assert_eq!(buffer.used(), 10);
        assert_eq!(buffer.append(b""), AppendOutcome::Ok);
    }

    #[test]
    fn overflow_leaves_buffered_bytes_intact() {
        let mut buffer = DelayedOutputBuffer::new(10);
        assert_eq!(buffer.append(b"0123456789"), AppendOutcome::Ok);
        assert_eq!(buffer.append(b"!"), AppendOutcome::Overflow);
        assert_eq!(buffer.used(), 10);
        assert_eq!(buffer.take_all(), b"0123456789".to_vec());
    }

    #[test]
    fn oversized_append_overflows_without_partial_write() {
        let mut buffer = DelayedOutputBuffer::new(10);
        assert_eq!(buffer.append(b"0123456789X"), AppendOutcome::Overflow);
        assert_eq!(buffer.used(), 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn overflow_persists_until_the_buffer_is_drained() {
        let mut buffer = DelayedOutputBuffer::new(5);
        assert_eq!(buffer.append(b"12345"), AppendOutcome::Ok);
        assert_eq!(buffer.append(b"6"), AppendOutcome::Overflow);
        assert_eq!(buffer.append(b"7"), AppendOutcome::Overflow);
        assert_eq!(buffer.take_all(), b"12345".to_vec());
        assert_eq!(buffer.append(b"6"), AppendOutcome::Ok);
        assert_eq!(buffer.take_all(), b"6".to_vec());
    }

    #[test]
    fn zero_capacity_rejects_every_byte() {
        let mut buffer = DelayedOutputBuffer::new(0);
        assert_eq!(buffer.append(b"a"), AppendOutcome::Overflow);
        assert!(buffer.is_empty());
    }

    #[test]
    fn production_cap_triggers_overflow_exactly_at_256_kib() {
        assert_eq!(DELAYED_OUTPUT_CAP, 256 * 1024);
        let mut buffer = DelayedOutputBuffer::new(DELAYED_OUTPUT_CAP);
        let chunk = vec![0x55_u8; 4096];
        for _ in 0..(DELAYED_OUTPUT_CAP / 4096) {
            assert_eq!(buffer.append(&chunk), AppendOutcome::Ok);
        }
        assert_eq!(buffer.used(), DELAYED_OUTPUT_CAP);
        assert_eq!(buffer.append(b"x"), AppendOutcome::Overflow);
        // The full delayed output is still retrievable in append order.
        let all = buffer.take_all();
        assert_eq!(all.len(), DELAYED_OUTPUT_CAP);
        assert!(all.iter().all(|&b| b == 0x55));
        // After the flush the buffer works again.
        assert_eq!(buffer.append(b"y"), AppendOutcome::Ok);
        assert_eq!(buffer.take_all(), b"y".to_vec());
    }
}
