#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Self-hosted Yonder relay application state.

pub mod identity;
pub mod registry;
pub mod service;

pub use identity::{FileIdentityStore, IdentityError, IdentityStore};
pub use registry::{Registry, RegistryError, ResolveLimiters};
pub use service::{RelayServeConfig, RelayServiceError, run_relay, run_relay_until};
