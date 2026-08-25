#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! End-user endpoint implementation for Yonder.

#[cfg(all(yonder_e2e_rebuild, not(debug_assertions)))]
compile_error!("yonder_e2e_rebuild is a test-only fault injection and cannot enter release builds");
#[cfg(test)]
pub(crate) static IN_PROCESS_NETWORK_GUARD: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(1));
#[cfg(test)]
static IN_PROCESS_THREAD_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
static NEXT_TEST_TCP_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(20_000);

#[cfg(test)]
pub(crate) fn in_process_test_guard() -> std::sync::MutexGuard<'static, ()> {
    IN_PROCESS_THREAD_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Returns a process-unique loopback port outside the common dynamic-port
/// ranges. The bind probe skips ports already owned by another process.
#[cfg(test)]
pub(crate) fn available_test_tcp_port() -> u16 {
    for _ in 20_000..30_000 {
        let port = NEXT_TEST_TCP_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(port < 30_000, "the test TCP port range is exhausted");
        if std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
    panic!("no test TCP port is available");
}

pub mod audit;
pub mod controller;
pub mod file_semantics;
pub mod host;
pub mod local_control;
pub mod network;
pub mod pake;
pub mod progress;
pub mod protocol;
pub mod shutdown;
pub mod terminal;
pub mod transfer;
pub mod transfer_prompt;
