use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream};
use tokio::sync::oneshot;
use tokio_util::io::SyncIoBridge;
use tokio_util::sync::DropGuard;
use yonder_core::TerminalSize;
use yonder_core::wire::terminal::TerminalHello;

const CHUNK_CAPACITY: usize = 16 * 1024;
const DUPLEX_CAPACITY: usize = 64 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// A fixed-capacity terminal payload; moving it through channels does not allocate.
pub struct TerminalChunk {
    bytes: [u8; CHUNK_CAPACITY],
    len: u16,
}

impl TerminalChunk {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; CHUNK_CAPACITY],
            len: 0,
        }
    }

    pub fn writable(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn set_len(&mut self, len: usize) -> Result<(), TerminalError> {
        self.len = u16::try_from(len)
            .ok()
            .filter(|length| usize::from(*length) <= CHUNK_CAPACITY)
            .ok_or(TerminalError::InvalidChunk)?;
        Ok(())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Default for TerminalChunk {
    fn default() -> Self {
        Self::new()
    }
}

/// Failures at the replaceable terminal backend boundary.
#[derive(Debug, Error)]
pub enum TerminalError {
    #[error("the platform PTY could not be opened")]
    Open,
    #[error("the current user's shell could not be started")]
    Spawn,
    #[error("a PTY I/O operation failed")]
    Io(#[source] std::io::Error),
    #[error("the PTY task stopped unexpectedly")]
    TaskStopped,
    #[error("the PTY task panicked")]
    TaskPanicked,
    #[error("the PTY child status could not be read")]
    ChildStatus(#[source] std::io::Error),
    #[error("the PTY child could not be terminated")]
    ChildTermination(#[source] std::io::Error),
    #[error("the PTY could not be resized")]
    Resize,
    #[error("the PTY output did not drain before the cleanup deadline")]
    OutputDrainTimeout,
    #[error("the PTY tasks did not stop before the cleanup deadline")]
    CleanupTimeout,
    #[error("the terminal payload length is invalid")]
    InvalidChunk,
}

/// Replaceable capability for opening the current user's terminal environment.
pub trait TerminalBackend {
    type Session: TerminalSession;

    fn open(
        &self,
        hello: TerminalHello,
    ) -> impl Future<Output = Result<Self::Session, TerminalError>> + Send;
}

/// Replaceable, independently-driven input capability for one terminal session.
pub trait TerminalInput: AsyncWrite + Unpin + Send {
    fn close(&mut self);
}

/// Replaceable lifecycle and I/O capability of one running terminal session.
pub trait TerminalSession: Send {
    type Input: TerminalInput;

    fn take_input(&mut self) -> Result<Self::Input, TerminalError>;

    fn resize(
        &mut self,
        size: TerminalSize,
    ) -> impl Future<Output = Result<(), TerminalError>> + Send;

    fn next(&mut self) -> impl Future<Output = Result<PtyEvent, TerminalError>> + Send;

    fn shutdown(self) -> impl Future<Output = Result<(), TerminalError>> + Send
    where
        Self: Sized;
}

/// Native ConPTY or Unix PTY implementation supplied by `portable-pty`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PortablePtyBackend;

impl TerminalBackend for PortablePtyBackend {
    type Session = PtySession;

    async fn open(&self, hello: TerminalHello) -> Result<Self::Session, TerminalError> {
        PtySession::open(hello).await
    }
}

struct PtyResources {
    master: Box<dyn MasterPty + Send>,
    reader: Box<dyn std::io::Read + Send>,
    writer: Box<dyn std::io::Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

fn open_resources(hello: &TerminalHello) -> Result<PtyResources, TerminalError> {
    let pair = native_pty_system()
        .openpty(to_pty_size(hello.size()))
        .map_err(|_| TerminalError::Open)?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| TerminalError::Open)?;
    let writer = pair.master.take_writer().map_err(|_| TerminalError::Open)?;
    let mut command = current_shell_command();
    command.cwd(std::env::current_dir().map_err(TerminalError::Io)?);
    if !hello.term().is_empty() {
        command.env("TERM", hello.term().as_str());
    } else {
        command.env_remove("TERM");
    }
    if !hello.color_term().is_empty() {
        command.env("COLORTERM", hello.color_term().as_str());
    } else {
        command.env_remove("COLORTERM");
    }
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|_| TerminalError::Spawn)?;
    drop(pair.slave);
    Ok(PtyResources {
        master: pair.master,
        reader,
        writer,
        child,
    })
}

fn current_shell_command() -> CommandBuilder {
    CommandBuilder::new_default_prog()
}

fn to_pty_size(size: TerminalSize) -> PtySize {
    PtySize {
        rows: size.rows(),
        cols: size.columns(),
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// A running PTY with bounded input/output and explicit lifecycle ownership.
pub struct PtySession {
    input: Option<DuplexStream>,
    output: DuplexStream,
    input_result: Option<oneshot::Receiver<Result<(), std::io::Error>>>,
    output_result: Option<oneshot::Receiver<Result<(), std::io::Error>>>,
    master: Option<Box<dyn MasterPty + Send>>,
    shutdown: tokio_util::sync::CancellationToken,
    cleanup_deadline: CleanupDeadline,
    _shutdown_guard: DropGuard,
    exit: Option<oneshot::Receiver<Result<ChildExit, TerminalError>>>,
    completed_exit: Option<Result<ChildExit, TerminalError>>,
    drain_deadline: Option<tokio::time::Instant>,
    output_closed: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// The independently-driven bounded input half of a native PTY session.
pub struct PtyInput {
    input: Option<DuplexStream>,
}

#[derive(Debug, Clone, Copy)]
struct ChildExit {
    code: u32,
    at: std::time::Instant,
}

#[derive(Debug, Clone, Default)]
struct CleanupDeadline(Arc<OnceLock<std::time::Instant>>);

impl CleanupDeadline {
    fn set(&self, deadline: std::time::Instant) {
        let _ = self.0.set(deadline);
    }

    fn get_or_start(&self) -> std::time::Instant {
        *self
            .0
            .get_or_init(|| std::time::Instant::now() + CLEANUP_TIMEOUT)
    }
}

struct StartedPty {
    master: Box<dyn MasterPty + Send>,
    writer_task: tokio::task::JoinHandle<()>,
    supervisor_task: tokio::task::JoinHandle<()>,
}

/// The small discriminator for a fixed-size PTY event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyEventKind {
    Output,
    Exited(u32),
}

/// A fixed-size event that avoids boxing terminal output blocks.
pub struct PtyEvent {
    kind: PtyEventKind,
    output: TerminalChunk,
}

impl PtyEvent {
    #[must_use]
    pub(crate) const fn output(output: TerminalChunk) -> Self {
        Self {
            kind: PtyEventKind::Output,
            output,
        }
    }

    #[must_use]
    pub(crate) const fn exited(code: u32) -> Self {
        Self {
            kind: PtyEventKind::Exited(code),
            output: TerminalChunk::new(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> PtyEventKind {
        self.kind
    }

    #[must_use]
    pub fn into_output(self) -> TerminalChunk {
        self.output
    }
}

impl PtySession {
    async fn open(hello: TerminalHello) -> Result<Self, TerminalError> {
        Self::open_with(hello, open_resources).await
    }

    async fn open_with<O>(hello: TerminalHello, open_resources: O) -> Result<Self, TerminalError>
    where
        O: FnOnce(&TerminalHello) -> Result<PtyResources, TerminalError> + Send + 'static,
    {
        let (input, input_bridge) = tokio::io::duplex(DUPLEX_CAPACITY);
        let (output_bridge, output) = tokio::io::duplex(DUPLEX_CAPACITY);
        let (input_result_tx, input_result_rx) = oneshot::channel();
        let (output_result_tx, output_result_rx) = oneshot::channel();
        let (exit_tx, exit_rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let shutdown_guard = shutdown.clone().drop_guard();
        let cleanup_deadline = CleanupDeadline::default();
        let task_shutdown = shutdown.clone();
        let task_deadline = cleanup_deadline.clone();
        let runtime = tokio::runtime::Handle::current();
        let reader_runtime = runtime.clone();

        let reader_task = tokio::task::spawn_blocking(move || {
            let resources = match open_resources(&hello) {
                Ok(resources) => resources,
                Err(error) => {
                    let _ = started_tx.send(Err(error));
                    return;
                }
            };
            let writer_runtime = reader_runtime.clone();
            let mut input_bridge = SyncIoBridge::new_with_handle(input_bridge, writer_runtime);
            let mut writer = resources.writer;
            let writer_task = tokio::task::spawn_blocking(move || {
                let result = copy_input(&mut input_bridge, writer.as_mut());
                drop(writer);
                let _ = input_result_tx.send(result);
            });
            let supervisor_shutdown = task_shutdown.clone();
            let supervisor_task = tokio::task::spawn_blocking(move || {
                let mut child = resources.child;
                let result = supervise_child(child.as_mut(), &supervisor_shutdown, &task_deadline);
                let _ = exit_tx.send(result);
            });
            let started = StartedPty {
                master: resources.master,
                writer_task,
                supervisor_task,
            };
            if let Err(error) = started_tx.send(Ok(started)) {
                task_shutdown.cancel();
                drop(error);
            }

            let mut output_bridge = SyncIoBridge::new_with_handle(output_bridge, runtime);
            let mut reader = resources.reader;
            let result = copy_output(reader.as_mut(), &mut output_bridge);
            let _ = output_result_tx.send(result);
        });

        let started = match started_rx.await {
            Ok(result) => result?,
            Err(_) => {
                let _ = reader_task.await;
                return Err(TerminalError::TaskPanicked);
            }
        };
        Ok(Self {
            input: Some(input),
            output,
            input_result: Some(input_result_rx),
            output_result: Some(output_result_rx),
            master: Some(started.master),
            shutdown,
            cleanup_deadline,
            _shutdown_guard: shutdown_guard,
            exit: Some(exit_rx),
            completed_exit: None,
            drain_deadline: None,
            output_closed: false,
            tasks: vec![reader_task, started.writer_task, started.supervisor_task],
        })
    }

    pub async fn send(&mut self, chunk: TerminalChunk) -> Result<(), TerminalError> {
        self.input
            .as_mut()
            .ok_or(TerminalError::TaskStopped)?
            .write_all(chunk.as_slice())
            .await
            .map_err(TerminalError::Io)
    }

    fn take_input(&mut self) -> Result<PtyInput, TerminalError> {
        Ok(PtyInput {
            input: Some(self.input.take().ok_or(TerminalError::TaskStopped)?),
        })
    }

    /// Applies the platform PTY input-EOF semantics after queued bytes are written.
    #[cfg(not(windows))]
    pub fn close_input(&mut self) {
        self.input.take();
    }

    /// ConPTY tears down the pseudoconsole when its writer closes, so the child owns exit.
    #[cfg(windows)]
    pub const fn close_input(&mut self) {}

    pub async fn receive(&mut self) -> Result<Option<TerminalChunk>, TerminalError> {
        if self.output_closed {
            return Ok(None);
        }
        let mut chunk = TerminalChunk::new();
        let length = self
            .output
            .read(chunk.writable())
            .await
            .map_err(TerminalError::Io)?;
        if length == 0 {
            self.output_closed = true;
            self.check_output_result().await?;
            return Ok(None);
        }
        chunk.set_len(length)?;
        Ok(Some(chunk))
    }

    pub async fn resize(&mut self, size: TerminalSize) -> Result<(), TerminalError> {
        self.master
            .as_ref()
            .ok_or(TerminalError::TaskStopped)?
            .resize(to_pty_size(size))
            .map_err(|_| TerminalError::Resize)
    }

    pub async fn wait(&mut self) -> Result<u32, TerminalError> {
        let exit = self
            .exit
            .take()
            .ok_or(TerminalError::TaskStopped)?
            .await
            .map_err(|_| TerminalError::TaskPanicked)??;
        Ok(exit.code)
    }

    /// Waits for either terminal output or authoritative child exit.
    pub async fn next(&mut self) -> Result<PtyEvent, TerminalError> {
        if self.completed_exit.is_some() {
            return self.drain_after_exit().await;
        }
        loop {
            let Some(exit) = self.exit.as_mut() else {
                return Err(TerminalError::TaskStopped);
            };
            let mut output = TerminalChunk::new();
            tokio::select! {
                read = self.output.read(output.writable()), if !self.output_closed => {
                    let length = read.map_err(TerminalError::Io)?;
                    if length == 0 {
                        self.output_closed = true;
                        self.check_output_result().await?;
                        continue;
                    }
                    output.set_len(length)?;
                    return Ok(PtyEvent::output(output));
                }
                result = wait_task_result(&mut self.input_result) => {
                    self.input_result.take();
                    result?;
                }
                result = exit => {
                    self.exit.take();
                    let result = result.map_err(|_| TerminalError::TaskPanicked)?;
                    self.input.take();
                    self.master.take();
                    self.drain_deadline = result.as_ref().ok().map(|exit| {
                        tokio::time::Instant::from_std(exit.at) + CLEANUP_TIMEOUT
                    });
                    self.completed_exit = Some(result);
                    return self.drain_after_exit().await;
                }
            }
        }
    }

    async fn drain_after_exit(&mut self) -> Result<PtyEvent, TerminalError> {
        if !self.output_closed {
            let deadline = self.drain_deadline.ok_or(TerminalError::TaskStopped)?;
            match tokio::time::timeout_at(deadline, self.receive()).await {
                Ok(Ok(Some(output))) => {
                    return Ok(PtyEvent::output(output));
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(TerminalError::OutputDrainTimeout),
            }
        }
        let exit = self
            .completed_exit
            .take()
            .ok_or(TerminalError::TaskStopped)??;
        Ok(exited_event(exit.code))
    }

    async fn check_output_result(&mut self) -> Result<(), TerminalError> {
        let Some(result) = self.output_result.take() else {
            return Ok(());
        };
        match result.await {
            Ok(result) => result.map_err(TerminalError::Io),
            Err(_) => Err(TerminalError::TaskPanicked),
        }
    }

    /// Stops the child, closes I/O, and joins every blocking task.
    pub async fn shutdown(self) -> Result<(), TerminalError> {
        self.shutdown_until(std::time::Instant::now() + CLEANUP_TIMEOUT)
            .await
    }

    async fn shutdown_until(mut self, deadline: std::time::Instant) -> Result<(), TerminalError> {
        let async_deadline = tokio::time::Instant::from_std(deadline);
        self.cleanup_deadline.set(deadline);
        self.input.take();
        self.master.take();
        self.shutdown.cancel();
        drop(self.output);
        let mut first_error = match self.exit.take() {
            Some(exit) => match tokio::time::timeout_at(async_deadline, exit).await {
                Ok(Ok(Ok(_))) => None,
                Ok(Ok(Err(error))) => Some(error),
                Ok(Err(_)) => Some(TerminalError::TaskPanicked),
                Err(_) => Some(TerminalError::CleanupTimeout),
            },
            None => None,
        };
        for mut task in self.tasks {
            match tokio::time::timeout_at(async_deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    first_error.get_or_insert(TerminalError::TaskPanicked);
                }
                Err(_) => {
                    first_error.get_or_insert(TerminalError::CleanupTimeout);
                }
            };
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl PtyInput {
    #[cfg(not(windows))]
    fn close(&mut self) {
        self.input.take();
    }

    #[cfg(windows)]
    const fn close(&mut self) {}
}

impl AsyncWrite for PtyInput {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "PTY input closed"));
        match input {
            Ok(input) => std::pin::Pin::new(input).poll_write(context, bytes),
            Err(error) => std::task::Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "PTY input closed"));
        match input {
            Ok(input) => std::pin::Pin::new(input).poll_flush(context),
            Err(error) => std::task::Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        #[cfg(windows)]
        {
            let _ = (&mut self, context);
            std::task::Poll::Ready(Ok(()))
        }
        #[cfg(not(windows))]
        {
            let input = self.input.as_mut().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "PTY input closed")
            });
            match input {
                Ok(input) => std::pin::Pin::new(input).poll_shutdown(context),
                Err(error) => std::task::Poll::Ready(Err(error)),
            }
        }
    }
}

impl TerminalInput for PtyInput {
    fn close(&mut self) {
        PtyInput::close(self);
    }
}

impl TerminalSession for PtySession {
    type Input = PtyInput;

    fn take_input(&mut self) -> Result<Self::Input, TerminalError> {
        PtySession::take_input(self)
    }

    fn resize(
        &mut self,
        size: TerminalSize,
    ) -> impl Future<Output = Result<(), TerminalError>> + Send {
        PtySession::resize(self, size)
    }

    fn next(&mut self) -> impl Future<Output = Result<PtyEvent, TerminalError>> + Send {
        PtySession::next(self)
    }

    fn shutdown(self) -> impl Future<Output = Result<(), TerminalError>> + Send {
        PtySession::shutdown(self)
    }
}

fn supervise_child(
    child: &mut dyn portable_pty::Child,
    shutdown: &tokio_util::sync::CancellationToken,
    cleanup_deadline: &CleanupDeadline,
) -> Result<ChildExit, TerminalError> {
    let mut kill_requested = false;
    let mut status_failure = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(error) = status_failure {
                    return Err(TerminalError::ChildStatus(error));
                }
                return Ok(observed_child_exit(status));
            }
            Ok(None) => {}
            Err(error) => {
                status_failure.get_or_insert(error);
            }
        }

        if (shutdown.is_cancelled() || status_failure.is_some()) && !kill_requested {
            if let Err(error) = child.kill() {
                if let Ok(Some(status)) = child.try_wait() {
                    return status_failure.map_or_else(
                        || Ok(observed_child_exit(status)),
                        |status| Err(TerminalError::ChildStatus(status)),
                    );
                }
                return Err(TerminalError::ChildTermination(error));
            }
            kill_requested = true;
        }

        let sleep = if kill_requested {
            let deadline = cleanup_deadline.get_or_start();
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return Err(status_failure
                    .map_or(TerminalError::CleanupTimeout, TerminalError::ChildStatus));
            };
            remaining.min(CHILD_POLL_INTERVAL)
        } else {
            CHILD_POLL_INTERVAL
        };
        std::thread::sleep(sleep);
    }
}

fn observed_child_exit(status: portable_pty::ExitStatus) -> ChildExit {
    ChildExit {
        code: status.exit_code(),
        at: std::time::Instant::now(),
    }
}

fn copy_input(
    input: &mut SyncIoBridge<DuplexStream>,
    writer: &mut dyn std::io::Write,
) -> Result<(), std::io::Error> {
    let mut buffer = [0_u8; CHUNK_CAPACITY];
    loop {
        let length = input.read(&mut buffer)?;
        if length == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..length])?;
        writer.flush()?;
    }
}

fn copy_output(
    reader: &mut dyn std::io::Read,
    output: &mut SyncIoBridge<DuplexStream>,
) -> Result<(), std::io::Error> {
    let mut buffer = [0_u8; CHUNK_CAPACITY];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            return Ok(());
        }
        output.write_all(&buffer[..length])?;
        output.flush()?;
    }
}

async fn wait_task_result(
    result: &mut Option<oneshot::Receiver<Result<(), std::io::Error>>>,
) -> Result<(), TerminalError> {
    let Some(result) = result.as_mut() else {
        return std::future::pending().await;
    };
    result
        .await
        .map_err(|_| TerminalError::TaskPanicked)?
        .map_err(TerminalError::Io)
}

fn exited_event(code: u32) -> PtyEvent {
    PtyEvent::exited(code)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CHUNK_CAPACITY, ChildExit, CleanupDeadline, DUPLEX_CAPACITY, PortablePtyBackend,
        PtyEventKind, PtyInput, PtySession, TerminalBackend, TerminalChunk, TerminalError,
        TerminalInput, TerminalSession, copy_input, copy_output, current_shell_command,
        exited_event, supervise_child, to_pty_size, wait_task_result,
    };
    use std::future::{Future as _, poll_fn};
    use std::io::{self, Cursor};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;
    use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream};
    use tokio::sync::oneshot;

    use tokio_util::io::SyncIoBridge;
    use yonder_core::wire::terminal::TerminalHello;
    use yonder_core::{TerminalSize, TerminalValue};

    #[tokio::test(flavor = "current_thread")]
    async fn closed_native_pty_input_has_consistent_async_write_semantics() {
        let mut input = PtyInput { input: None };
        assert_eq!(
            input.write_all(b"input").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            input.flush().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        #[cfg(windows)]
        input.shutdown().await.unwrap();
        #[cfg(not(windows))]
        assert_eq!(
            input.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        TerminalInput::close(&mut input);
    }

    #[test]
    fn chunk_and_size_boundaries_are_exact() {
        let mut chunk = TerminalChunk::default();
        chunk.writable()[..3].copy_from_slice(b"yon");
        chunk.set_len(3).unwrap();
        assert_eq!(chunk.as_slice(), b"yon");
        assert!(chunk.set_len(16 * 1024 + 1).is_err());

        let size = to_pty_size(TerminalSize::new(120, 40).unwrap());
        assert_eq!((size.cols, size.rows), (120, 40));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_backend_opens_resizes_and_shuts_down_the_current_shell() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm-256color").unwrap(),
            TerminalValue::new("truecolor").unwrap(),
        );
        let mut session = PortablePtyBackend.open(hello).await.unwrap();
        TerminalSession::resize(&mut session, TerminalSize::new(100, 30).unwrap())
            .await
            .unwrap();
        TerminalSession::shutdown(session).await.unwrap();

        let empty_environment = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("").unwrap(),
            TerminalValue::new("").unwrap(),
        );
        let session = PortablePtyBackend.open(empty_environment).await.unwrap();
        TerminalSession::shutdown(session).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn startup_reports_resource_failure_and_blocking_task_panic() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm").unwrap(),
            TerminalValue::new("truecolor").unwrap(),
        );
        assert!(matches!(
            PtySession::open_with(hello.clone(), |_| Err(TerminalError::Open)).await,
            Err(TerminalError::Open)
        ));
        assert!(matches!(
            PtySession::open_with(hello, |_| panic!("synthetic PTY startup panic")).await,
            Err(TerminalError::TaskPanicked)
        ));
    }

    #[test]
    fn shell_selection_uses_portable_pty_default_program_semantics() {
        assert!(current_shell_command().is_default_prog());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn input_bridge_backpressures_at_capacity_and_drains_after_half_close() {
        let initial = patterned_bytes(DUPLEX_CAPACITY, 0);
        let tail = patterned_bytes(CHUNK_CAPACITY + 37, DUPLEX_CAPACITY);
        let (mut input, bridge) = tokio::io::duplex(DUPLEX_CAPACITY);
        input.write_all(&initial).await.unwrap();

        let first_tail_poll =
            poll_fn(|context| Poll::Ready(Pin::new(&mut input).poll_write(context, &tail[..1])))
                .await;
        assert!(first_tail_poll.is_pending());

        let runtime = tokio::runtime::Handle::current();
        let copier = tokio::task::spawn_blocking(move || {
            let mut bridge = SyncIoBridge::new_with_handle(bridge, runtime);
            let mut copied = Vec::with_capacity(DUPLEX_CAPACITY + CHUNK_CAPACITY + 37);
            copy_input(&mut bridge, &mut copied)?;
            Ok::<_, io::Error>(copied)
        });
        input.write_all(&tail).await.unwrap();
        input.shutdown().await.unwrap();

        let copied = copier.await.unwrap().unwrap();
        assert_eq!(copied.len(), initial.len() + tail.len());
        assert_eq!(&copied[..initial.len()], initial.as_slice());
        assert_eq!(&copied[initial.len()..], tail.as_slice());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn output_bridge_preserves_large_payload_and_tail_before_eof() {
        let payload = patterned_bytes(DUPLEX_CAPACITY + CHUNK_CAPACITY + 37, 11);
        let expected = payload.clone();
        let (bridge, mut output) = tokio::io::duplex(DUPLEX_CAPACITY);
        let runtime = tokio::runtime::Handle::current();
        let copier = tokio::task::spawn_blocking(move || {
            let mut reader = Cursor::new(payload);
            let mut bridge = SyncIoBridge::new_with_handle(bridge, runtime);
            copy_output(&mut reader, &mut bridge)
        });

        let mut received = Vec::with_capacity(expected.len());
        output.read_to_end(&mut received).await.unwrap();
        copier.await.unwrap().unwrap();

        assert_eq!(received, expected);
        assert_eq!(
            &received[received.len() - 37..],
            &expected[expected.len() - 37..]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_copy_loops_preserve_every_reachable_io_failure_boundary() {
        async fn input_failure(writer: FailingWrite) -> io::Result<()> {
            let (mut input, bridge) = tokio::io::duplex(16);
            input.write_all(b"input").await.unwrap();
            input.shutdown().await.unwrap();
            let runtime = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                let mut bridge = SyncIoBridge::new_with_handle(bridge, runtime);
                let mut writer = writer;
                copy_input(&mut bridge, &mut writer)
            })
            .await
            .unwrap()
        }

        assert!(input_failure(FailingWrite::write()).await.is_err());
        assert!(input_failure(FailingWrite::flush()).await.is_err());

        let (bridge, _output) = tokio::io::duplex(1);
        let runtime = tokio::runtime::Handle::current();
        let read_failure = tokio::task::spawn_blocking(move || {
            let mut bridge = SyncIoBridge::new_with_handle(bridge, runtime);
            copy_output(&mut FailingRead, &mut bridge)
        })
        .await
        .unwrap();
        assert!(read_failure.is_err());

        let (bridge, output) = tokio::io::duplex(1);
        drop(output);
        let runtime = tokio::runtime::Handle::current();
        let write_failure = tokio::task::spawn_blocking(move || {
            let mut bridge = SyncIoBridge::new_with_handle(bridge, runtime);
            copy_output(&mut Cursor::new(b"output"), &mut bridge)
        })
        .await
        .unwrap();
        assert!(write_failure.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synthetic_session_covers_bounded_io_and_terminal_errors() {
        let (mut session, mut controls) = synthetic_session();
        let mut chunk = TerminalChunk::new();
        chunk.writable()[0] = 7;
        chunk.set_len(1).unwrap();
        session.send(chunk).await.unwrap();
        let mut input = [0_u8; 1];
        controls.input.read_exact(&mut input).await.unwrap();
        assert_eq!(input, [7]);
        drop(controls.input);
        let mut closed = TerminalChunk::new();
        closed.writable()[0] = 1;
        closed.set_len(1).unwrap();
        assert!(matches!(
            session.send(closed).await,
            Err(TerminalError::Io(_))
        ));

        controls.output.write_all(&[9]).await.unwrap();
        assert_eq!(session.receive().await.unwrap().unwrap().as_slice(), &[9]);
        controls.output.shutdown().await.unwrap();
        controls
            .output_result
            .send(Err(io::Error::other("output")))
            .unwrap();
        assert!(matches!(session.receive().await, Err(TerminalError::Io(_))));
        assert!(session.receive().await.unwrap().is_none());
        assert!(matches!(
            session.resize(TerminalSize::new(120, 40).unwrap()).await,
            Err(TerminalError::TaskStopped)
        ));
        controls.exit.send(Ok(child_exit(23))).unwrap();
        assert_eq!(session.wait().await.unwrap(), 23);
        assert!(matches!(
            session.wait().await,
            Err(TerminalError::TaskStopped)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synthetic_session_surfaces_task_channels_and_platform_input_close() {
        let (mut failed_input, controls) = synthetic_session();
        controls
            .input_result
            .send(Err(io::Error::other("input")))
            .unwrap();
        assert!(matches!(
            failed_input.next().await,
            Err(TerminalError::Io(_))
        ));

        let (mut failed_output, mut controls) = synthetic_session();
        controls.output.shutdown().await.unwrap();
        drop(controls.output_result);
        assert!(matches!(
            failed_output.receive().await,
            Err(TerminalError::TaskPanicked)
        ));

        let (mut failed_wait, controls) = synthetic_session();
        drop(controls.exit);
        assert!(matches!(
            failed_wait.wait().await,
            Err(TerminalError::TaskPanicked)
        ));

        let (mut closed_input, _controls) = synthetic_session();
        closed_input.close_input();
        #[cfg(windows)]
        assert!(closed_input.input.is_some());
        #[cfg(not(windows))]
        assert!(closed_input.input.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synthetic_eof_and_shutdown_cover_deferred_terminal_failures() {
        let (mut eof_before_exit, mut controls) = synthetic_session();
        controls.output.shutdown().await.unwrap();
        controls.output_result.send(Ok(())).unwrap();
        let exit = controls.exit;
        let exit_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            exit.send(Ok(child_exit(31))).unwrap();
        });

        assert_eq!(
            eof_before_exit.next().await.unwrap().kind(),
            PtyEventKind::Exited(31)
        );
        let mut after_exit = TerminalChunk::new();
        after_exit.writable()[0] = 1;
        after_exit.set_len(1).unwrap();
        assert!(matches!(
            eof_before_exit.send(after_exit).await,
            Err(TerminalError::TaskStopped)
        ));
        eof_before_exit.check_output_result().await.unwrap();
        exit_task.await.unwrap();

        let (panicked, controls) = synthetic_session();
        drop(controls.exit);
        assert!(matches!(
            panicked.shutdown().await,
            Err(TerminalError::TaskPanicked)
        ));

        let (timed_out, controls) = synthetic_session();
        assert!(matches!(
            timed_out.shutdown_until(std::time::Instant::now()).await,
            Err(TerminalError::CleanupTimeout)
        ));
        drop(controls);

        let mut absent = None;
        let future = wait_task_result(&mut absent);
        tokio::pin!(future);
        let first_poll = poll_fn(|context| Poll::Ready(future.as_mut().poll(context))).await;
        assert!(first_poll.is_pending());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authoritative_exit_drains_tail_and_preserves_output_failure() {
        let (mut draining, mut controls) = synthetic_session();
        controls.exit.send(Ok(child_exit(29))).unwrap();
        let producer = tokio::spawn(async move {
            controls.output.write_all(b"tail").await.unwrap();
            controls.output.shutdown().await.unwrap();
            controls.output_result.send(Ok(())).unwrap();
        });
        let event = draining.next().await.unwrap();
        assert_eq!(event.kind(), PtyEventKind::Output);
        assert_eq!(event.into_output().as_slice(), b"tail");
        assert_eq!(
            draining.next().await.unwrap().kind(),
            PtyEventKind::Exited(29)
        );
        producer.await.unwrap();

        let (mut failed, mut controls) = synthetic_session();
        failed.completed_exit = Some(Ok(child_exit(0)));
        failed.drain_deadline =
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
        controls.output.shutdown().await.unwrap();
        controls
            .output_result
            .send(Err(io::Error::other("tail")))
            .unwrap();
        assert!(matches!(failed.next().await, Err(TerminalError::Io(_))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synthetic_events_drain_output_before_exit_and_report_failures() {
        let (mut session, mut controls) = synthetic_session();
        controls.output.write_all(b"yon").await.unwrap();
        let event = session.next().await.unwrap();
        assert_eq!(event.kind(), PtyEventKind::Output);
        assert_eq!(event.into_output().as_slice(), b"yon");

        session.completed_exit = Some(Ok(child_exit(17)));
        session.drain_deadline =
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
        controls.output.shutdown().await.unwrap();
        controls.output_result.send(Ok(())).unwrap();
        let event = session.next().await.unwrap();
        assert_eq!(event.kind(), PtyEventKind::Exited(17));
        assert!(event.into_output().as_slice().is_empty());

        let (mut failed, mut controls) = synthetic_session();
        failed.completed_exit = Some(Err(TerminalError::Io(io::Error::other("exit"))));
        failed.drain_deadline =
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
        controls.output.shutdown().await.unwrap();
        controls.output_result.send(Ok(())).unwrap();
        assert!(matches!(failed.next().await, Err(TerminalError::Io(_))));

        let (mut stopped, controls) = synthetic_session();
        stopped.exit.take();
        drop(controls);
        assert!(matches!(
            stopped.next().await,
            Err(TerminalError::TaskStopped)
        ));
        assert_eq!(exited_event(3).kind(), PtyEventKind::Exited(3));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_and_shutdown_deadlines_are_absolute() {
        let (mut draining, _controls) = synthetic_session();
        draining.completed_exit = Some(Ok(child_exit(0)));
        draining.drain_deadline = Some(tokio::time::Instant::now());
        assert!(matches!(
            draining.next().await,
            Err(TerminalError::OutputDrainTimeout)
        ));

        let (mut session, controls) = synthetic_session();
        let SyntheticControls { exit, .. } = controls;
        exit.send(Ok(child_exit(0))).unwrap();
        session.tasks.push(tokio::spawn(async {}));
        session.shutdown().await.unwrap();

        let (mut panicked, controls) = synthetic_session();
        let SyntheticControls { exit, .. } = controls;
        exit.send(Ok(child_exit(0))).unwrap();
        panicked
            .tasks
            .push(tokio::spawn(async { panic!("test panic") }));
        assert!(matches!(
            panicked.shutdown().await,
            Err(TerminalError::TaskPanicked)
        ));

        let (mut timed_out, controls) = synthetic_session();
        let SyntheticControls { exit, .. } = controls;
        exit.send(Ok(child_exit(0))).unwrap();
        for _ in 0..3 {
            timed_out.tasks.push(tokio::spawn(std::future::pending()));
        }
        assert!(matches!(
            timed_out.shutdown_until(std::time::Instant::now()).await,
            Err(TerminalError::CleanupTimeout)
        ));
    }

    #[test]
    fn child_supervisor_owns_termination_and_exit_polling() {
        let killed = Arc::new(AtomicBool::new(false));
        let mut child = FakeChild::running(Arc::clone(&killed), true, false);
        let shutdown = tokio_util::sync::CancellationToken::new();
        shutdown.cancel();
        let deadline = CleanupDeadline::default();
        deadline.set(std::time::Instant::now() + std::time::Duration::from_secs(1));

        let exit = supervise_child(&mut child, &shutdown, &deadline).unwrap();
        assert_eq!(exit.code, 7);
        assert!(killed.load(Ordering::Acquire));

        let naturally_killed = Arc::new(AtomicBool::new(false));
        let mut natural = FakeChild::exited(Arc::clone(&naturally_killed));
        let natural_exit = supervise_child(
            &mut natural,
            &tokio_util::sync::CancellationToken::new(),
            &CleanupDeadline::default(),
        )
        .unwrap();
        assert_eq!(natural_exit.code, 7);
        assert!(!naturally_killed.load(Ordering::Acquire));

        let auto_killed = Arc::new(AtomicBool::new(false));
        let mut auto_deadline_child = FakeChild::running(Arc::clone(&auto_killed), true, false);
        let auto_shutdown = tokio_util::sync::CancellationToken::new();
        auto_shutdown.cancel();
        let auto_deadline = CleanupDeadline::default();
        assert_eq!(
            supervise_child(&mut auto_deadline_child, &auto_shutdown, &auto_deadline)
                .unwrap()
                .code,
            7
        );
        assert!(auto_killed.load(Ordering::Acquire));
        assert!(auto_deadline.0.get().is_some());
    }

    #[test]
    fn child_supervisor_reports_kill_failure_and_cleanup_timeout() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        shutdown.cancel();
        let deadline = CleanupDeadline::default();
        deadline.set(std::time::Instant::now() + std::time::Duration::from_secs(1));
        let mut kill_fails = FakeChild::running(Arc::new(AtomicBool::new(false)), false, true);
        assert!(matches!(
            supervise_child(&mut kill_fails, &shutdown, &deadline),
            Err(TerminalError::ChildTermination(_))
        ));

        let mut exited_during_kill =
            FakeChild::running(Arc::new(AtomicBool::new(false)), true, true);
        assert_eq!(
            supervise_child(&mut exited_during_kill, &shutdown, &deadline)
                .unwrap()
                .code,
            7
        );

        let expired = CleanupDeadline::default();
        expired.set(std::time::Instant::now());
        let mut never_exits = FakeChild::running(Arc::new(AtomicBool::new(false)), false, false);
        assert!(matches!(
            supervise_child(&mut never_exits, &shutdown, &expired),
            Err(TerminalError::CleanupTimeout)
        ));

        let status_killed = Arc::new(AtomicBool::new(false));
        let mut status_fails = FakeChild::status_fails(Arc::clone(&status_killed));
        assert!(matches!(
            supervise_child(&mut status_fails, &shutdown, &expired),
            Err(TerminalError::ChildStatus(_))
        ));
        assert!(status_killed.load(Ordering::Acquire));

        let recovered_killed = Arc::new(AtomicBool::new(false));
        let mut recovered_status =
            FakeChild::status_fails_then_exits(Arc::clone(&recovered_killed), false);
        assert!(matches!(
            supervise_child(&mut recovered_status, &shutdown, &deadline),
            Err(TerminalError::ChildStatus(_))
        ));
        assert!(recovered_killed.load(Ordering::Acquire));

        let mut exited_after_failed_kill =
            FakeChild::status_fails_then_exits(Arc::new(AtomicBool::new(false)), true);
        assert!(matches!(
            supervise_child(&mut exited_after_failed_kill, &shutdown, &deadline),
            Err(TerminalError::ChildStatus(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn session_drop_cancels_supervision_and_shutdown_preserves_kill_failure() {
        let (session, controls) = synthetic_session();
        let cancellation = session.shutdown.clone();
        drop(controls);
        drop(session);
        assert!(cancellation.is_cancelled());

        let (session, controls) = synthetic_session();
        let SyntheticControls { exit, .. } = controls;
        exit.send(Err(TerminalError::ChildTermination(io::Error::other(
            "kill",
        ))))
        .unwrap();
        assert!(matches!(
            session.shutdown().await,
            Err(TerminalError::ChildTermination(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "release-candidate stress gate"]
    async fn stress_10000_terminal_cancel_resize_and_child_exit_interleavings_are_bounded() {
        let size = TerminalSize::new(120, 40).unwrap();
        for schedule in 0_u16..10_000 {
            let (mut session, controls) = synthetic_session();
            let cancellation = session.shutdown.clone();
            if schedule & 1 == 0 {
                cancellation.cancel();
            }
            assert!(matches!(
                session.resize(size).await,
                Err(TerminalError::TaskStopped)
            ));

            if schedule & 2 == 0 {
                controls
                    .exit
                    .send(Ok(child_exit(u32::from(schedule))))
                    .unwrap();
                assert_eq!(session.wait().await.unwrap(), u32::from(schedule));
            } else {
                drop(controls.exit);
                assert!(matches!(
                    session.wait().await,
                    Err(TerminalError::TaskPanicked)
                ));
            }
            drop(session);
            assert!(cancellation.is_cancelled());
        }
    }

    struct SyntheticControls {
        input: DuplexStream,
        output: DuplexStream,
        input_result: oneshot::Sender<Result<(), io::Error>>,
        output_result: oneshot::Sender<Result<(), io::Error>>,
        exit: oneshot::Sender<Result<ChildExit, TerminalError>>,
    }

    struct FailingRead;

    impl io::Read for FailingRead {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic read failure"))
        }
    }

    #[derive(Clone, Copy)]
    enum WriteFailure {
        Write,
        Flush,
    }

    struct FailingWrite(WriteFailure);

    impl FailingWrite {
        const fn write() -> Self {
            Self(WriteFailure::Write)
        }

        const fn flush() -> Self {
            Self(WriteFailure::Flush)
        }
    }

    impl io::Write for FailingWrite {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            match self.0 {
                WriteFailure::Write => Err(io::Error::other("synthetic write failure")),
                WriteFailure::Flush => Ok(buffer.len()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            match self.0 {
                WriteFailure::Write => Ok(()),
                WriteFailure::Flush => Err(io::Error::other("synthetic flush failure")),
            }
        }
    }

    fn synthetic_session() -> (PtySession, SyntheticControls) {
        let (input, input_control) = tokio::io::duplex(64 * 1024);
        let (output_control, output) = tokio::io::duplex(64 * 1024);
        let (input_result_tx, input_result_rx) = oneshot::channel();
        let (output_result_tx, output_result_rx) = oneshot::channel();
        let (exit_tx, exit_rx) = oneshot::channel();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let shutdown_guard = shutdown.clone().drop_guard();
        (
            PtySession {
                input: Some(input),
                output,
                input_result: Some(input_result_rx),
                output_result: Some(output_result_rx),
                master: None,
                shutdown,
                cleanup_deadline: CleanupDeadline::default(),
                _shutdown_guard: shutdown_guard,
                exit: Some(exit_rx),
                completed_exit: None,
                drain_deadline: None,
                output_closed: false,
                tasks: Vec::new(),
            },
            SyntheticControls {
                input: input_control,
                output: output_control,
                input_result: input_result_tx,
                output_result: output_result_tx,
                exit: exit_tx,
            },
        )
    }

    #[derive(Debug)]
    struct FakeChild {
        killed: Arc<AtomicBool>,
        natural_exit: bool,
        exit_after_kill: bool,
        kill_fails: bool,
        poll_failures_remaining: usize,
    }

    impl FakeChild {
        fn running(killed: Arc<AtomicBool>, exit_after_kill: bool, kill_fails: bool) -> Self {
            Self {
                killed,
                natural_exit: false,
                exit_after_kill,
                kill_fails,
                poll_failures_remaining: 0,
            }
        }

        fn exited(killed: Arc<AtomicBool>) -> Self {
            Self {
                killed,
                natural_exit: true,
                exit_after_kill: false,
                kill_fails: false,
                poll_failures_remaining: 0,
            }
        }

        fn status_fails(killed: Arc<AtomicBool>) -> Self {
            Self {
                killed,
                natural_exit: false,
                exit_after_kill: false,
                kill_fails: false,
                poll_failures_remaining: usize::MAX,
            }
        }

        fn status_fails_then_exits(killed: Arc<AtomicBool>, kill_fails: bool) -> Self {
            Self {
                killed,
                natural_exit: false,
                exit_after_kill: true,
                kill_fails,
                poll_failures_remaining: 1,
            }
        }
    }

    impl portable_pty::ChildKiller for FakeChild {
        fn kill(&mut self) -> io::Result<()> {
            self.killed.store(true, Ordering::Release);
            if self.kill_fails {
                Err(io::Error::other("kill"))
            } else {
                Ok(())
            }
        }

        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            panic!("the child supervisor must terminate the owned Child directly")
        }
    }

    impl portable_pty::Child for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<portable_pty::ExitStatus>> {
            if self.poll_failures_remaining > 0 {
                self.poll_failures_remaining -= 1;
                return Err(io::Error::other("status"));
            }
            if self.natural_exit || (self.exit_after_kill && self.killed.load(Ordering::Acquire)) {
                Ok(Some(portable_pty::ExitStatus::with_exit_code(7)))
            } else {
                Ok(None)
            }
        }

        fn wait(&mut self) -> io::Result<portable_pty::ExitStatus> {
            panic!("the child supervisor must not perform an unbounded wait")
        }

        fn process_id(&self) -> Option<u32> {
            None
        }

        #[cfg(windows)]
        fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
            None
        }
    }

    fn child_exit(code: u32) -> ChildExit {
        ChildExit {
            code,
            at: std::time::Instant::now(),
        }
    }

    fn patterned_bytes(length: usize, offset: usize) -> Vec<u8> {
        (offset..offset + length)
            .map(|index| (index % 251) as u8)
            .collect()
    }
}
