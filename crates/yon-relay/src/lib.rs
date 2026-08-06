#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Self-hosted Yonder relay application state.

pub mod enterprise;
pub mod identity;
pub mod registry;
pub mod secret_file;
pub mod service;
pub mod session;

pub use enterprise::{
    CallbackExternalUrl, EnterpriseAuthConfig, EnterpriseConfigError, ProviderSecrets,
};
pub use identity::{FileIdentityStore, IdentityError, IdentityStore};
pub use registry::{Registry, RegistryError, ResolveLimiters};
pub use secret_file::{SecretFileError, SecretFilePolicy, SystemSecretFilePolicy};
pub use service::{RelayServeConfig, RelayServiceError, run_relay, run_relay_until};
pub use session::{
    EnterpriseFailure, EnterpriseResolvePhase, EnterpriseResolveSession, MemberAdmission,
    MemberIdentity, OAuthState, RequestId, TransitionError,
};
