#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! End-user endpoint implementation for Yonder.

#[cfg(all(yonder_e2e_rebuild, not(debug_assertions)))]
compile_error!("yonder_e2e_rebuild is a test-only fault injection and cannot enter release builds");

pub mod controller;
pub mod host;
pub mod network;
pub mod pake;
pub mod progress;
pub mod protocol;
pub mod shutdown;
pub mod terminal;
