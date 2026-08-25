//! Safe, bounded replay of the controller display timeline.
//!
//! Recorded bytes are consumed only by [`vt100::Parser`]. Rendering reads
//! the parser's visible cells and emits local [`crossterm`] operations, so
//! remote escape sequences and terminal side-effect requests are never
//! copied to the user's terminal.

use std::borrow::Cow;
use std::io::{self, IsTerminal as _, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;
use vt100::Callbacks;
use yonder_core::wire::audit_container::RecordType;

use crate::audit::verify::{
    PlatformAnchorLookup, StreamAction, StreamError, VerificationReport, VerificationState,
    VerifyError, stream_frames, verify_files,
};

const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;
const MAX_ROWS: u16 = 512;
const MAX_COLS: u16 = 1024;
const LOCAL_RECORD_PREFIX_LEN: usize = 40;
const RESIZE_RECORD_LEN: usize = 45;

/// Input paths for one replay operation.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    pub controller_path: PathBuf,
    pub peer_path: Option<PathBuf>,
}

/// A replay that ran, or a verified state that is not replayable.
#[derive(Debug, Clone)]
pub enum ReplayResult {
    Replayed(ReplayReport),
    Refused {
        state: VerificationState,
        reason: &'static str,
    },
}

/// Side-effecting terminal requests consumed by the virtual terminal.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FilteredControls {
    pub title: u64,
    pub clipboard: u64,
    pub resize_request: u64,
    pub unhandled: u64,
}

impl FilteredControls {
    #[must_use]
    pub const fn total(self) -> u64 {
        self.title + self.clipboard + self.resize_request + self.unhandled
    }
}

/// Summary of a replayed display timeline.
#[derive(Debug, Clone)]
pub struct ReplayReport {
    pub state: VerificationState,
    pub unpaired: bool,
    pub interrupted: bool,
    pub filtered: FilteredControls,
    pub bells: u64,
    pub display_records: u64,
    pub display_bytes: u64,
    pub final_screen: (u16, u16),
    /// Plain visible text from the bounded virtual screen. The CLI does not
    /// print this field after replay; it supports programmatic inspection and
    /// safety regression tests without exposing raw terminal bytes.
    pub final_text: String,
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("the audit file changed while it was being replayed")]
    Changed,
    #[error("the audit replay stream is invalid")]
    Stream(#[source] StreamError),
    #[error("the replay display could not be written")]
    Display(#[source] io::Error),
}

/// Verifies, safely replays, and verifies the same session again to detect
/// replacement or mutation between admission and completion.
pub fn replay_session(config: &ReplayConfig) -> Result<ReplayResult, ReplayError> {
    let initial = verify_files(
        &config.controller_path,
        config.peer_path.as_deref(),
        &PlatformAnchorLookup,
    )?;
    if !controller_path_matches(&initial, &config.controller_path) {
        return Ok(ReplayResult::Refused {
            state: initial.state,
            reason: "the replay source is not the controller audit record",
        });
    }
    if let Some(reason) = refusal_reason(initial.state, config.peer_path.is_none()) {
        return Ok(ReplayResult::Refused {
            state: initial.state,
            reason,
        });
    }

    let interactive = io::stdout().is_terminal();
    let (rows, cols) = if interactive {
        crossterm::terminal::size()
            .map(|(cols, rows)| clamp_size(rows, cols))
            .unwrap_or((DEFAULT_ROWS, DEFAULT_COLS))
    } else {
        (DEFAULT_ROWS, DEFAULT_COLS)
    };
    let mut replay = ReplayMachine::new(rows, cols);

    if interactive {
        let guard = TerminalGuard::enter().map_err(ReplayError::Display)?;
        let mut stdout = io::stdout().lock();
        replay
            .run(&config.controller_path, Some(&mut stdout))
            .map_err(map_run_error)?;
        drop(stdout);
        drop(guard);
    } else {
        replay
            .run(&config.controller_path, None)
            .map_err(map_run_error)?;
    }

    let final_verification = verify_files(
        &config.controller_path,
        config.peer_path.as_deref(),
        &PlatformAnchorLookup,
    )?;
    if !same_verified_session(&initial, &final_verification)
        || !controller_path_matches(&final_verification, &config.controller_path)
    {
        return Err(ReplayError::Changed);
    }

    Ok(ReplayResult::Replayed(
        replay.report(initial.state, config.peer_path.is_none()),
    ))
}

fn refusal_reason(state: VerificationState, unpaired: bool) -> Option<&'static str> {
    match state {
        VerificationState::VerifiedComplete | VerificationState::ConsistentCompleteUnanchored => {
            None
        }
        VerificationState::IntactUnpaired if unpaired => None,
        VerificationState::IntactUnpaired => {
            Some("the controller and peer files do not form a pair")
        }
        VerificationState::MatchedInterruptedPrefix => {
            Some("the session was interrupted; only the last common checkpoint is verified")
        }
        VerificationState::Mismatch => Some("the two audit files do not match"),
        VerificationState::Tampered => Some("the audit file is tampered"),
    }
}

fn controller_path_matches(report: &VerificationReport, path: &Path) -> bool {
    report
        .controller
        .as_ref()
        .is_some_and(|controller| controller.path == path)
}

fn same_verified_session(left: &VerificationReport, right: &VerificationReport) -> bool {
    left.state == right.state
        && left.session_id == right.session_id
        && left.controller.as_ref().map(|file| {
            (
                file.fingerprint,
                file.local_event_count,
                file.shared_counts,
                file.finalized,
                file.truncated_tail,
            )
        }) == right.controller.as_ref().map(|file| {
            (
                file.fingerprint,
                file.local_event_count,
                file.shared_counts,
                file.finalized,
                file.truncated_tail,
            )
        })
}

fn map_run_error(error: RunError) -> ReplayError {
    match error {
        RunError::Stream(error) => ReplayError::Stream(error),
        RunError::Display(error) => ReplayError::Display(error),
    }
}

#[derive(Debug, Error)]
enum RunError {
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Display(#[from] io::Error),
}

#[derive(Debug, Default, Clone, Copy)]
struct ReplayCallbacks {
    filtered: FilteredControls,
    bells: u64,
}

impl Callbacks for ReplayCallbacks {
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.bells += 1;
    }

    fn visual_bell(&mut self, _: &mut vt100::Screen) {
        self.bells += 1;
    }

    fn resize(&mut self, _: &mut vt100::Screen, _: (u16, u16)) {
        self.filtered.resize_request += 1;
    }

    fn set_window_icon_name(&mut self, _: &mut vt100::Screen, _: &[u8]) {
        self.filtered.title += 1;
    }

    fn set_window_title(&mut self, _: &mut vt100::Screen, _: &[u8]) {
        self.filtered.title += 1;
    }

    fn copy_to_clipboard(&mut self, _: &mut vt100::Screen, _: &[u8], _: &[u8]) {
        self.filtered.clipboard += 1;
    }

    fn paste_from_clipboard(&mut self, _: &mut vt100::Screen, _: &[u8]) {
        self.filtered.clipboard += 1;
    }

    fn unhandled_char(&mut self, _: &mut vt100::Screen, _: char) {
        self.filtered.unhandled += 1;
    }

    fn unhandled_control(&mut self, _: &mut vt100::Screen, _: u8) {
        self.filtered.unhandled += 1;
    }

    fn unhandled_escape(&mut self, _: &mut vt100::Screen, _: Option<u8>, _: Option<u8>, _: u8) {
        self.filtered.unhandled += 1;
    }

    fn unhandled_csi(
        &mut self,
        _: &mut vt100::Screen,
        _: Option<u8>,
        _: Option<u8>,
        _: &[&[u16]],
        _: char,
    ) {
        self.filtered.unhandled += 1;
    }

    fn unhandled_osc(&mut self, _: &mut vt100::Screen, _: &[&[u8]]) {
        self.filtered.unhandled += 1;
    }
}

struct ReplayMachine {
    parser: vt100::Parser<ReplayCallbacks>,
    viewport: (u16, u16),
    display_records: u64,
    display_bytes: u64,
    interrupted: bool,
}

impl ReplayMachine {
    fn new(rows: u16, cols: u16) -> Self {
        let (rows, cols) = clamp_size(rows, cols);
        Self {
            parser: vt100::Parser::new_with_callbacks(rows, cols, 0, ReplayCallbacks::default()),
            viewport: (rows, cols),
            display_records: 0,
            display_bytes: 0,
            interrupted: false,
        }
    }

    fn run(&mut self, path: &Path, output: Option<&mut dyn Write>) -> Result<(), RunError> {
        self.run_with_interrupt(path, output, poll_interrupt)
    }

    fn run_with_interrupt<F>(
        &mut self,
        path: &Path,
        mut output: Option<&mut dyn Write>,
        mut interrupt: F,
    ) -> Result<(), RunError>
    where
        F: FnMut() -> io::Result<bool>,
    {
        let mut display_error = None;
        let stream_result = stream_frames(path, &mut |record_type, payload| {
            match record_type {
                RecordType::LocalDisplayBytes => {
                    let display = payload
                        .get(LOCAL_RECORD_PREFIX_LEN..)
                        .ok_or(StreamError::Tampered("the display record is invalid"))?;
                    self.display_records += 1;
                    self.display_bytes += display.len() as u64;
                    self.parser.process(display);
                    if let Some(output) = output.as_deref_mut() {
                        if let Err(error) = render_screen(
                            self.parser.screen(),
                            self.viewport,
                            &mut WriterRef(output),
                        ) {
                            display_error = Some(error);
                            return Err(StreamError::Tampered("the replay display failed"));
                        }
                        let interrupted = match interrupt() {
                            Ok(interrupted) => interrupted,
                            Err(error) => {
                                display_error = Some(error);
                                return Err(StreamError::Tampered("the replay display failed"));
                            }
                        };
                        if interrupted {
                            self.interrupted = true;
                            return Ok(StreamAction::Stop);
                        }
                    }
                }
                RecordType::LocalResizeEvent => {
                    if payload.len() != RESIZE_RECORD_LEN {
                        return Err(StreamError::Tampered("the resize record is invalid"));
                    }
                    let cols = u16::from_be_bytes([payload[41], payload[42]]);
                    let rows = u16::from_be_bytes([payload[43], payload[44]]);
                    let (rows, cols) = clamp_size(rows, cols);
                    self.parser.screen_mut().set_size(rows, cols);
                    if let Some(output) = output.as_deref_mut()
                        && let Err(error) = render_screen(
                            self.parser.screen(),
                            self.viewport,
                            &mut WriterRef(output),
                        )
                    {
                        display_error = Some(error);
                        return Err(StreamError::Tampered("the replay display failed"));
                    }
                }
                _ => {}
            }
            Ok(StreamAction::Continue)
        });
        if let Some(error) = display_error {
            return Err(RunError::Display(error));
        }
        stream_result?;
        Ok(())
    }

    fn report(&self, state: VerificationState, unpaired: bool) -> ReplayReport {
        let callbacks = self.parser.callbacks();
        ReplayReport {
            state,
            unpaired,
            interrupted: self.interrupted,
            filtered: callbacks.filtered,
            bells: callbacks.bells,
            display_records: self.display_records,
            display_bytes: self.display_bytes,
            final_screen: self.parser.screen().size(),
            final_text: safe_visible_text(self.parser.screen()),
        }
    }
}

fn clamp_size(rows: u16, cols: u16) -> (u16, u16) {
    (rows.clamp(1, MAX_ROWS), cols.clamp(1, MAX_COLS))
}

fn safe_visible_text(screen: &vt100::Screen) -> String {
    screen
        .contents()
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CellStyle {
    foreground: vt100::Color,
    background: vt100::Color,
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    inverse: bool,
}

impl CellStyle {
    fn from_cell(cell: &vt100::Cell) -> Self {
        Self {
            foreground: cell.fgcolor(),
            background: cell.bgcolor(),
            bold: cell.bold(),
            dim: cell.dim(),
            italic: cell.italic(),
            underline: cell.underline(),
            inverse: cell.inverse(),
        }
    }
}

struct WriterRef<'a>(&'a mut dyn Write);

impl Write for WriterRef<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn render_screen<W: Write>(
    screen: &vt100::Screen,
    viewport: (u16, u16),
    output: &mut W,
) -> io::Result<()> {
    use crossterm::cursor::{Hide, MoveTo, Show};
    use crossterm::style::{
        Attribute, Print, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor,
    };
    use crossterm::terminal::{Clear, ClearType};

    let (screen_rows, screen_cols) = screen.size();
    let rows = screen_rows.min(viewport.0);
    let cols = screen_cols.min(viewport.1);
    crossterm::queue!(output, Hide)?;
    let mut emitted_style = None;
    for row in 0..rows {
        crossterm::queue!(output, MoveTo(0, row), Clear(ClearType::CurrentLine))?;
        for col in 0..cols {
            let Some(cell) = screen.cell(row, col) else {
                continue;
            };
            if cell.is_wide_continuation() {
                continue;
            }
            let style = CellStyle::from_cell(cell);
            if emitted_style != Some(style) {
                crossterm::queue!(
                    output,
                    SetAttribute(Attribute::Reset),
                    ResetColor,
                    SetForegroundColor(crossterm_color(style.foreground)),
                    SetBackgroundColor(crossterm_color(style.background))
                )?;
                for (enabled, attribute) in [
                    (style.bold, Attribute::Bold),
                    (style.dim, Attribute::Dim),
                    (style.italic, Attribute::Italic),
                    (style.underline, Attribute::Underlined),
                    (style.inverse, Attribute::Reverse),
                ] {
                    if enabled {
                        crossterm::queue!(output, SetAttribute(attribute))?;
                    }
                }
                emitted_style = Some(style);
            }
            crossterm::queue!(output, Print(safe_cell_contents(cell.contents())))?;
        }
    }
    crossterm::queue!(output, SetAttribute(Attribute::Reset), ResetColor)?;
    if screen.hide_cursor() {
        crossterm::queue!(output, Hide)?;
    } else {
        let (row, col) = screen.cursor_position();
        crossterm::queue!(
            output,
            MoveTo(
                col.min(viewport.1.saturating_sub(1)),
                row.min(viewport.0.saturating_sub(1))
            ),
            Show
        )?;
    }
    output.flush()
}

fn safe_cell_contents(contents: &str) -> Cow<'_, str> {
    if contents.is_empty() {
        return Cow::Borrowed(" ");
    }
    if contents.chars().all(|character| !character.is_control()) {
        return Cow::Borrowed(contents);
    }
    let filtered: String = contents
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    if filtered.is_empty() {
        Cow::Borrowed(" ")
    } else {
        Cow::Owned(filtered)
    }
}

fn crossterm_color(color: vt100::Color) -> crossterm::style::Color {
    match color {
        vt100::Color::Default => crossterm::style::Color::Reset,
        vt100::Color::Idx(index) => crossterm::style::Color::AnsiValue(index),
        vt100::Color::Rgb(r, g, b) => crossterm::style::Color::Rgb { r, g, b },
    }
}

fn poll_interrupt() -> io::Result<bool> {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    while crossterm::event::poll(std::time::Duration::ZERO)? {
        if matches!(
            crossterm::event::read()?,
            Event::Key(KeyEvent {
                code: KeyCode::Char('c' | 'C'),
                modifiers,
                ..
            }) if modifiers.contains(KeyModifiers::CONTROL)
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        use crossterm::cursor::Hide;
        use crossterm::terminal::{Clear, ClearType, EnterAlternateScreen};
        crossterm::terminal::enable_raw_mode()?;
        if let Err(error) = crossterm::execute!(
            io::stdout(),
            EnterAlternateScreen,
            Hide,
            Clear(ClearType::All)
        ) {
            let _ = crossterm::terminal::disable_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        use crossterm::cursor::Show;
        use crossterm::terminal::LeaveAlternateScreen;
        let _ = crossterm::execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::audit::verify::tests::{
        Endpoint, build_pair_with_controller_display, build_pair_with_controller_display_chunks,
    };
    use std::fs;
    use tempfile::tempdir;
    use yonder_core::wire::audit_container::{CONTAINER_HEADER_LEN, encode_frame_header};

    fn frame(record_type: RecordType, payload: &[u8]) -> Vec<u8> {
        let mut frame = encode_frame_header(1 + payload.len() as u32).to_vec();
        frame.push(record_type.code());
        frame.extend_from_slice(payload);
        frame
    }

    fn write_test_stream(source: &Path, target: &Path, frames: &[Vec<u8>]) {
        let source = fs::read(source).unwrap();
        let mut bytes = source[..CONTAINER_HEADER_LEN].to_vec();
        for frame in frames {
            bytes.extend_from_slice(frame);
        }
        fs::write(target, bytes).unwrap();
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("expected display failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("expected display failure"))
        }
    }

    struct FlushFailingWriter;

    impl Write for FlushFailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("expected flush failure"))
        }
    }

    #[derive(Default)]
    struct WriteCounter {
        calls: usize,
    }

    impl Write for WriteCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailOnWrite {
        target: usize,
        calls: usize,
    }

    impl Write for FailOnWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.calls == self.target {
                return Err(io::Error::other("expected staged display failure"));
            }
            self.calls += 1;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn vt100_consumes_dangerous_sequences_without_rendering_their_payloads() {
        let mut machine = ReplayMachine::new(24, 80);
        machine.parser.process(
            b"safe\x1b]2;TITLE_SECRET\x07\x1b]52;c;CLIPBOARD_SECRET\x07\
              \x1bP1;2|DCS_SECRET\x1b\\after\x07",
        );
        let mut rendered = Vec::new();
        render_screen(machine.parser.screen(), machine.viewport, &mut rendered).unwrap();
        assert!(safe_visible_text(machine.parser.screen()).contains("safeafter"));
        assert!(
            !rendered
                .windows(b"TITLE_SECRET".len())
                .any(|w| w == b"TITLE_SECRET")
        );
        assert!(
            !rendered
                .windows(b"CLIPBOARD_SECRET".len())
                .any(|w| w == b"CLIPBOARD_SECRET")
        );
        assert!(
            !rendered
                .windows(b"DCS_SECRET".len())
                .any(|w| w == b"DCS_SECRET")
        );
        assert!(machine.parser.callbacks().filtered.total() >= 2);
        assert_eq!(machine.parser.callbacks().bells, 1);
    }

    #[test]
    fn replay_dimensions_are_bounded() {
        assert_eq!(clamp_size(0, 0), (1, 1));
        assert_eq!(clamp_size(24, 80), (24, 80));
        assert_eq!(clamp_size(u16::MAX, u16::MAX), (MAX_ROWS, MAX_COLS));
    }

    #[test]
    fn callbacks_account_for_every_filtered_side_effect() {
        let mut callbacks = ReplayCallbacks::default();
        let mut parser = vt100::Parser::new(2, 2, 0);
        callbacks.audible_bell(parser.screen_mut());
        callbacks.visual_bell(parser.screen_mut());
        callbacks.resize(parser.screen_mut(), (9, 9));
        callbacks.set_window_icon_name(parser.screen_mut(), b"icon");
        callbacks.set_window_title(parser.screen_mut(), b"title");
        callbacks.copy_to_clipboard(parser.screen_mut(), b"c", b"secret");
        callbacks.paste_from_clipboard(parser.screen_mut(), b"c");
        callbacks.unhandled_char(parser.screen_mut(), '\u{fffd}');
        callbacks.unhandled_control(parser.screen_mut(), 0xff);
        callbacks.unhandled_escape(parser.screen_mut(), Some(b'?'), None, b'x');
        callbacks.unhandled_csi(parser.screen_mut(), None, None, &[&[1]], 'x');
        callbacks.unhandled_osc(parser.screen_mut(), &[b"unknown"]);

        assert_eq!(callbacks.bells, 2);
        assert_eq!(callbacks.filtered.title, 2);
        assert_eq!(callbacks.filtered.clipboard, 2);
        assert_eq!(callbacks.filtered.resize_request, 1);
        assert_eq!(callbacks.filtered.unhandled, 5);
        assert_eq!(callbacks.filtered.total(), 10);
    }

    #[test]
    fn renderer_emits_bounded_styles_colors_and_cursor_states() {
        let mut parser = vt100::Parser::new(2, 3, 0);
        parser.process(b"\x1b[1;2;3;4;7;38;5;123;48;2;1;2;3mA\xe7\x95\x8c\x1b[?25l");
        let mut rendered = Vec::new();
        render_screen(parser.screen(), (1, 3), &mut rendered).unwrap();
        assert!(!rendered.is_empty());
        assert!(safe_visible_text(parser.screen()).contains("A"));

        parser.process(b"\x1b[0m\x1b[?25h\rB");
        rendered.clear();
        render_screen(parser.screen(), (u16::MAX, u16::MAX), &mut rendered).unwrap();
        assert!(!rendered.is_empty());

        assert!(matches!(
            render_screen(parser.screen(), (2, 3), &mut FlushFailingWriter),
            Err(error) if error.kind() == io::ErrorKind::Other
        ));
    }

    #[test]
    fn renderer_propagates_failure_from_every_output_stage() {
        let mut parser = vt100::Parser::new(2, 4, 0);
        parser.process(b"\x1b[1;3;4;38;5;123;48;2;1;2;3mAB\x1b[0m\rC");
        let mut counter = WriteCounter::default();
        render_screen(parser.screen(), (2, 4), &mut counter).unwrap();
        assert!(
            counter.calls > 10,
            "the fixture must exercise styled output"
        );

        for target in 0..counter.calls {
            let mut writer = FailOnWrite { target, calls: 0 };
            assert!(
                render_screen(parser.screen(), (2, 4), &mut writer).is_err(),
                "write call {target} was not propagated"
            );
        }
    }

    #[test]
    fn cell_contents_filter_removes_control_codepoints() {
        assert!(matches!(safe_cell_contents(""), Cow::Borrowed(" ")));
        assert!(matches!(
            safe_cell_contents("plain"),
            Cow::Borrowed("plain")
        ));
        assert!(matches!(
            safe_cell_contents("\u{0000}\u{0007}"),
            Cow::Borrowed(" ")
        ));
        assert_eq!(safe_cell_contents("A\u{0000}B"), "AB");
    }

    #[test]
    fn run_error_mapping_preserves_stream_and_display_causes() {
        assert!(matches!(
            map_run_error(RunError::Stream(StreamError::Tampered("bad stream"))),
            ReplayError::Stream(StreamError::Tampered("bad stream"))
        ));
        assert!(matches!(
            map_run_error(RunError::Display(io::Error::other("bad display"))),
            ReplayError::Display(error) if error.kind() == io::ErrorKind::Other
        ));
    }

    #[test]
    fn refusal_policy_accepts_only_the_replayable_states() {
        assert_eq!(
            refusal_reason(VerificationState::VerifiedComplete, false),
            None
        );
        assert_eq!(
            refusal_reason(VerificationState::ConsistentCompleteUnanchored, false),
            None
        );
        assert_eq!(
            refusal_reason(VerificationState::IntactUnpaired, true),
            None
        );
        for state in [
            VerificationState::IntactUnpaired,
            VerificationState::MatchedInterruptedPrefix,
            VerificationState::Mismatch,
            VerificationState::Tampered,
        ] {
            assert!(refusal_reason(state, false).is_some());
        }
    }

    #[tokio::test]
    async fn complete_pair_replays_controller_display_through_vt100() {
        let directory = tempdir().unwrap();
        let chunks = vec![b"hello \x1b[31mred\x1b[0m".to_vec(), b"\rfinal".to_vec()];
        let pair = build_pair_with_controller_display_chunks(
            directory.path(),
            Endpoint::Memory(1),
            Endpoint::Memory(101),
            &chunks,
        )
        .await;
        let result = replay_session(&ReplayConfig {
            controller_path: pair.controller_path,
            peer_path: Some(pair.host_path),
        })
        .unwrap();
        let ReplayResult::Replayed(report) = result else {
            panic!("a consistent complete pair must replay");
        };
        assert_eq!(
            report.state,
            VerificationState::ConsistentCompleteUnanchored
        );
        assert_eq!(report.display_records, 2);
        assert_eq!(
            report.display_bytes,
            chunks.iter().map(Vec::len).sum::<usize>() as u64
        );
        assert!(!report.unpaired);
        assert!(!report.interrupted);
        assert_eq!(report.final_screen, (30, 100));
        assert!(report.final_text.contains("final red"));
    }

    #[tokio::test]
    async fn intact_controller_record_replays_without_a_peer_file() {
        let directory = tempdir().unwrap();
        let pair = build_pair_with_controller_display(
            directory.path(),
            Endpoint::Memory(3),
            Endpoint::Memory(103),
            b"unpaired display",
        )
        .await;
        let result = replay_session(&ReplayConfig {
            controller_path: pair.controller_path,
            peer_path: None,
        })
        .unwrap();
        let ReplayResult::Replayed(report) = result else {
            panic!("an intact controller record must be replayable without its peer");
        };
        assert_eq!(report.state, VerificationState::IntactUnpaired);
        assert!(report.unpaired);
        assert!(report.final_text.contains("unpaired display"));
    }

    #[tokio::test]
    async fn mismatched_pair_is_refused_before_any_display_is_rendered() {
        let directory = tempdir().unwrap();
        let first = build_pair_with_controller_display(
            directory.path(),
            Endpoint::Memory(4),
            Endpoint::Memory(104),
            b"first",
        )
        .await;
        let other_directory = tempdir().unwrap();
        let second = build_pair_with_controller_display(
            other_directory.path(),
            Endpoint::Memory(5),
            Endpoint::Memory(105),
            b"second",
        )
        .await;
        let result = replay_session(&ReplayConfig {
            controller_path: first.controller_path,
            peer_path: Some(second.host_path),
        })
        .unwrap();
        assert!(matches!(
            result,
            ReplayResult::Refused {
                state: VerificationState::Mismatch,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn replay_machine_rejects_malformed_local_records_and_display_failures() {
        let directory = tempdir().unwrap();
        let pair = build_pair_with_controller_display(
            directory.path(),
            Endpoint::Memory(6),
            Endpoint::Memory(106),
            b"source",
        )
        .await;

        let short_display = directory.path().join("short-display.yonaudit");
        write_test_stream(
            &pair.controller_path,
            &short_display,
            &[frame(RecordType::LocalDisplayBytes, b"short")],
        );
        assert!(matches!(
            ReplayMachine::new(24, 80).run(&short_display, None),
            Err(RunError::Stream(StreamError::Tampered(
                "the display record is invalid"
            )))
        ));

        let short_resize = directory.path().join("short-resize.yonaudit");
        write_test_stream(
            &pair.controller_path,
            &short_resize,
            &[frame(
                RecordType::LocalResizeEvent,
                &[0; RESIZE_RECORD_LEN - 1],
            )],
        );
        assert!(matches!(
            ReplayMachine::new(24, 80).run(&short_resize, None),
            Err(RunError::Stream(StreamError::Tampered(
                "the resize record is invalid"
            )))
        ));

        let mut resize = [0_u8; RESIZE_RECORD_LEN];
        resize[41..43].copy_from_slice(&u16::MAX.to_be_bytes());
        resize[43..45].copy_from_slice(&0_u16.to_be_bytes());
        let valid = directory.path().join("valid-local.yonaudit");
        let mut display = vec![0_u8; LOCAL_RECORD_PREFIX_LEN];
        display.extend_from_slice(b"visible");
        write_test_stream(
            &pair.controller_path,
            &valid,
            &[
                frame(RecordType::LocalResizeEvent, &resize),
                frame(RecordType::LocalDisplayBytes, &display),
            ],
        );
        let mut output = Vec::new();
        let mut machine = ReplayMachine::new(24, 80);
        machine
            .run_with_interrupt(&valid, Some(&mut output), || Ok(false))
            .unwrap();
        let report = machine.report(VerificationState::IntactUnpaired, true);
        assert_eq!(report.final_screen, (1, MAX_COLS));
        assert_eq!(report.display_records, 1);
        assert_eq!(report.display_bytes, 7);
        assert!(report.final_text.contains("visible"));
        assert!(!output.is_empty());

        assert!(matches!(
            ReplayMachine::new(24, 80).run_with_interrupt(
                &valid,
                Some(&mut FailingWriter),
                || Ok(false),
            ),
            Err(RunError::Display(error)) if error.kind() == io::ErrorKind::Other
        ));

        let display_only = directory.path().join("display-only.yonaudit");
        write_test_stream(
            &pair.controller_path,
            &display_only,
            &[frame(RecordType::LocalDisplayBytes, &display)],
        );
        assert!(matches!(
            ReplayMachine::new(24, 80).run_with_interrupt(
                &display_only,
                Some(&mut FailingWriter),
                || Ok(false),
            ),
            Err(RunError::Display(error)) if error.kind() == io::ErrorKind::Other
        ));

        let mut interrupted = ReplayMachine::new(24, 80);
        let interrupted_path = directory.path().join("interrupted-local.yonaudit");
        let mut first = vec![0_u8; LOCAL_RECORD_PREFIX_LEN];
        first.extend_from_slice(b"first");
        let mut second = vec![0_u8; LOCAL_RECORD_PREFIX_LEN];
        second.extend_from_slice(b"second");
        write_test_stream(
            &pair.controller_path,
            &interrupted_path,
            &[
                frame(RecordType::LocalDisplayBytes, &first),
                frame(RecordType::LocalDisplayBytes, &second),
            ],
        );
        interrupted
            .run_with_interrupt(&interrupted_path, Some(&mut Vec::new()), || Ok(true))
            .unwrap();
        assert!(interrupted.interrupted);
        assert_eq!(interrupted.display_records, 1);
        assert!(
            interrupted
                .report(VerificationState::IntactUnpaired, true)
                .final_text
                .contains("first")
        );

        let mut non_interactive = ReplayMachine::new(24, 80);
        non_interactive
            .run_with_interrupt(&interrupted_path, None, || {
                panic!("non-interactive replay must not poll local terminal input")
            })
            .unwrap();
        assert_eq!(non_interactive.display_records, 2);

        assert!(matches!(
            ReplayMachine::new(24, 80).run_with_interrupt(
                &valid,
                Some(&mut Vec::new()),
                || Err(io::Error::other("expected input failure")),
            ),
            Err(RunError::Display(error)) if error.kind() == io::ErrorKind::Other
        ));
    }

    #[tokio::test]
    async fn host_record_is_never_accepted_as_the_display_source() {
        let directory = tempdir().unwrap();
        let pair = build_pair_with_controller_display(
            directory.path(),
            Endpoint::Memory(2),
            Endpoint::Memory(102),
            b"controller display",
        )
        .await;
        let result = replay_session(&ReplayConfig {
            controller_path: pair.host_path,
            peer_path: None,
        })
        .unwrap();
        assert!(matches!(result, ReplayResult::Refused { .. }));
    }
}
