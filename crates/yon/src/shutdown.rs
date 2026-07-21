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
