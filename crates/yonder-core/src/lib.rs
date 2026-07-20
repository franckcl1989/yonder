#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Type-safe domain and wire protocol primitives shared by Yonder processes.

pub mod code;
pub mod domain;
pub mod error;
pub mod pake;
pub mod random;
pub mod rate;
pub mod resource;
pub mod roster;
pub mod secret;
pub mod session;
pub mod time;
pub mod wire;

pub use code::{ConnectionCode, Locator, PakeSecret};
pub use domain::{PeerIdBytes, RetryAfter, TerminalSize, TerminalValue};
pub use error::{CodeError, DomainError, ProtocolError};
pub use pake::Pake;
pub use random::{IdentitySeed, OsSecureRandom, RandomError, SecureRandom};
pub use rate::{DirectRateLimiter, RateLimit};
pub use resource::{
    CircuitBytes, CircuitCapacity, CircuitDuration, CircuitRelayLimits, RegistrationCapacity,
    RegistrationLimits, RelayResourceConfig, RelayResourceError, RelayResourceField,
    ReservationDuration, ResolveConcurrency, ResolveLimits, ResolveRate, SourceLimiterCapacity,
    SourceLimiterIdle, SourceRegistrationCapacity,
};
pub use roster::{ConnectionRoster, RosterError};
pub use secret::SecretDocument;
pub use session::{SessionEvent, TargetSession, TargetSessionState, TransitionError};
pub use time::{MonotonicClock, MonotonicTime, SystemClock};
