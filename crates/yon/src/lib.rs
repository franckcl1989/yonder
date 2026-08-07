#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! End-user endpoint implementation for Yonder.

#[cfg(all(yonder_e2e_rebuild, not(debug_assertions)))]
compile_error!("yonder_e2e_rebuild is a test-only fault injection and cannot enter release builds");

#[cfg(test)]
pub(crate) static IN_PROCESS_NETWORK_GUARD: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(1));

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
