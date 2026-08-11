#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Self-hosted Yonder relay application state.

pub mod callback;
pub mod callback_session;
pub mod enterprise;
pub mod enterprise_resolve;
pub mod exchange;
pub mod identity;
pub mod provider;
pub mod registry;
pub mod secret_file;
pub mod service;
pub mod session;
pub mod verifier;

pub use callback::{CallbackHandler, CallbackResult, CallbackServer, CallbackServerError};
pub use callback_session::{
    CallbackEntry, CallbackRegistry, CallbackRegistryError, CallbackSessionHandler,
};
pub use enterprise::{
    CallbackExternalUrl, EnterpriseAuthConfig, EnterpriseConfigError, ProviderSecrets,
};
pub use exchange::ExchangeClient;
pub use identity::{FileIdentityStore, IdentityError, IdentityStore};
pub use provider::{ProviderCredentials, ProviderError, ProviderField};
pub use registry::{Registry, RegistryError, ResolveLimiters};
pub use secret_file::{SecretFileError, SecretFilePolicy, SystemSecretFilePolicy};
pub use service::{
    EnterpriseContext, RelayServeConfig, RelayServiceError, run_relay, run_relay_until,
};
pub use session::{
    EnterpriseFailure, EnterpriseResolvePhase, EnterpriseResolveSession, MemberAdmission,
    MemberIdentity, OAuthState, RequestId, TransitionError,
};
pub use verifier::{ExchangeTransport, VerifyError, verify_member};
