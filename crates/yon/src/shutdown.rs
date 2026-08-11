//! Cross-platform endpoint shutdown notification built on Tokio's native signal support.

#[cfg(unix)]
pub async fn endpoint_shutdown_signal() -> Result<(), std::io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
        _ = hangup.recv() => {}
    }
    Ok(())
}

#[cfg(windows)]
pub async fn endpoint_shutdown_signal() -> Result<(), std::io::Error> {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};

    let mut interrupt = ctrl_c()?;
    let mut console_break = ctrl_break()?;
    let mut console_close = ctrl_close()?;
    let mut console_logoff = ctrl_logoff()?;
    let mut console_shutdown = ctrl_shutdown()?;
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = console_break.recv() => {}
        _ = console_close.recv() => {}
        _ = console_logoff.recv() => {}
        _ = console_shutdown.recv() => {}
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub async fn endpoint_shutdown_signal() -> Result<(), std::io::Error> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The shutdown future registers every console-event source and must
    /// stay pending until a real console event arrives; it must never
    /// resolve spuriously on its own.
    ///
    /// A real CTRL_C/CTRL_BREAK event cannot be synthesised from safe Rust
    /// without the Win32 console API, so the observable behaviour under
    /// test is that the future remains pending (and un-errored) while no
    /// event is delivered.
    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn windows_shutdown_signal_stays_pending_without_a_console_event() {
        let handle = tokio::spawn(endpoint_shutdown_signal());
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !handle.is_finished(),
            "the shutdown signal future resolved without a console event"
        );
        handle.abort();
        assert!(
            handle.await.is_err(),
            "an aborted shutdown task must not complete successfully"
        );
    }

    /// A real SIGTERM delivered by a child process resolves the future with
    /// `Ok(())`: the tokio signal handler intercepts the signal before the
    /// default termination disposition can run. `bash -c "kill -TERM <pid>"`
    /// is used because bash's `kill` builtin is present on every CI image.
    ///
    /// The killer child sleeps first so the OS handler is guaranteed to be
    /// installed before the signal arrives: the handler registers on the
    /// signal future's first poll, which happens when this task starts
    /// awaiting it. Without the delay a loaded CI runner could deliver the
    /// signal before installation, which would terminate the whole test
    /// process instead of resolving the future.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn unix_shutdown_signal_resolves_on_sigterm() {
        let pid = std::process::id();
        let mut killer = std::process::Command::new("bash")
            .args(["-c", &format!("sleep 1; kill -TERM {pid}")])
            .spawn()
            .expect("bash must run on the unix CI images");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::spawn(endpoint_shutdown_signal()),
        )
        .await
        .expect("the shutdown future must resolve after SIGTERM")
        .expect("the shutdown task must not panic");
        result.expect("the shutdown future must complete with Ok(())");
        let status = killer.wait().expect("the killer child must exit");
        assert!(status.success(), "the killer child must succeed");
    }
}
