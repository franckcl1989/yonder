//! Single-owner enterprise authentication session state machine.
//!
//! Mirrors the EnterpriseResolveSession model of the 0.1.2 design: the
//! session is held in memory only, never persisted, single use, and bound
//! to one connect substream. Its lifetime is bounded, it dies on
//! disconnect, timeout or relay restart, and it cannot be resumed,
//! transferred or reused.

use std::time::Duration;
use thiserror::Error;
use yonder_core::{EnterpriseProvider, Locator, MonotonicTime, PeerIdBytes, SecureRandom};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// How long an enterprise session may stay alive after creation.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// An opaque request identifier used in redacted logs only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u64);

impl RequestId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:016x}", self.0)
    }
}

/// A single-use OAuth CSRF state created only after the provider is chosen.
///
/// `Debug` is deliberately redacted: the design forbids logging state.
#[derive(Clone, PartialEq, Eq, Hash, Zeroize)]
pub struct OAuthState([u8; Self::LEN]);

impl OAuthState {
    pub const LEN: usize = 32;

    /// Generates a fresh single-use state from the OS CSPRNG.
    pub fn generate(random: &mut impl SecureRandom) -> Result<Self, TransitionError> {
        let mut bytes = [0_u8; Self::LEN];
        random.try_fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Reconstructs a state from its wire bytes; only an exact-length
    /// state is accepted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransitionError> {
        let Ok(bytes) = <[u8; Self::LEN]>::try_from(bytes) else {
            return Err(TransitionError::InvalidState);
        };
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl std::fmt::Debug for OAuthState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuthState(<redacted>)")
    }
}

/// The bounded member identity bytes held only while authenticating.
///
/// The content is provider-specific member data; the session only carries
/// it and destroys it immediately once membership has been validated.
/// `Debug` is deliberately redacted: the design forbids logging identity.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MemberIdentity {
    bytes: [u8; Self::MAX_LEN],
    len: u16,
}

impl std::fmt::Debug for MemberIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemberIdentity")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl MemberIdentity {
    pub const MAX_LEN: usize = 256;

    /// Bounds and stores the provider member identity.
    pub fn new(bytes: &[u8]) -> Result<Self, TransitionError> {
        if bytes.is_empty() || bytes.len() > Self::MAX_LEN {
            return Err(TransitionError::InvalidIdentity);
        }
        let mut identity = Self {
            bytes: [0_u8; Self::MAX_LEN],
            len: bytes.len() as u16,
        };
        identity.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(identity)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// The phase of one enterprise authentication transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterpriseResolvePhase {
    /// The start request arrived; nothing has been sent yet.
    Created,
    /// The available providers were offered; selection is pending.
    ProviderSelection,
    /// The provider was chosen and the browser authentication is pending.
    Authenticating,
    /// Membership was validated and the identity has been destroyed.
    Authenticated,
    /// The internal locator resolution is running.
    Resolving,
    /// The final response was sent; the session is spent.
    Completed,
    /// The session was cancelled.
    Cancelled,
    /// The session lifetime expired.
    Expired,
    /// Authentication failed or the member was rejected.
    Failed(EnterpriseFailure),
    /// The target locator is not available.
    Unavailable,
}

impl EnterpriseResolvePhase {
    /// Whether the session has reached a terminal phase.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::Expired | Self::Failed(_) | Self::Unavailable
        )
    }
}

/// Redacted enterprise authentication failure kinds used in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterpriseFailure {
    /// The provider platform returned an anomaly.
    Platform,
    /// The user rejected the request or is not a valid internal member.
    UserRejected,
    /// The OAuth state was missing, mismatched or replayed.
    InvalidState,
}

/// The outcome of a member validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAdmission {
    /// The member belongs to the configured enterprise and is active.
    Admitted,
    /// The member was rejected and the identity has been destroyed.
    Rejected,
}

/// Illegal session transitions and construction failures.
#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("the enterprise session cannot perform this transition")]
    InvalidTransition,
    #[error("the enterprise session is already terminal")]
    Terminal,
    #[error("the OAuth state is missing, mismatched or has already been used")]
    InvalidState,
    #[error("the member identity is empty or too large")]
    InvalidIdentity,
    #[error("the OS random source failed: {0}")]
    Random(#[from] yonder_core::RandomError),
}

/// One enterprise authentication transaction.
///
/// Owned by a single task; every transition is a guarded method on this
/// type so contradictory state combinations cannot be constructed.
/// `Debug` is deliberately redacted: the design forbids logging identity,
/// state and PeerId.
pub struct EnterpriseResolveSession {
    request_id: RequestId,
    locator: Locator,
    deadline: MonotonicTime,
    phase: EnterpriseResolvePhase,
    provider: Option<EnterpriseProvider>,
    oauth_state: Option<OAuthState>,
    identity: Option<MemberIdentity>,
    target_peer: Option<PeerIdBytes>,
}

impl EnterpriseResolveSession {
    /// Creates a session in the `Created` phase with a bounded lifetime.
    #[must_use]
    pub fn new(request_id: RequestId, locator: Locator, now: MonotonicTime) -> Self {
        let deadline = now.checked_add(SESSION_LIFETIME).unwrap_or(now);
        Self {
            request_id,
            locator,
            deadline,
            phase: EnterpriseResolvePhase::Created,
            provider: None,
            oauth_state: None,
            identity: None,
            target_peer: None,
        }
    }

    /// The redacted request identifier used in logs.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// The locator this session will resolve after authentication.
    #[must_use]
    pub const fn locator(&self) -> Locator {
        self.locator
    }

    /// The phase the session is currently in.
    #[must_use]
    pub const fn phase(&self) -> EnterpriseResolvePhase {
        self.phase
    }

    /// The chosen provider, once selection has happened.
    #[must_use]
    pub const fn provider(&self) -> Option<EnterpriseProvider> {
        self.provider
    }

    /// The session lifetime deadline.
    #[must_use]
    pub const fn deadline(&self) -> MonotonicTime {
        self.deadline
    }

    /// Whether the session has reached a terminal phase.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.phase.is_terminal()
    }

    /// Whether the session has expired at the given time.
    #[must_use]
    pub fn is_expired(&self, now: MonotonicTime) -> bool {
        now >= self.deadline
    }

    /// Whether member identity bytes are currently held. Never exposed
    /// beyond this boolean; contents are destroyed on validation.
    #[must_use]
    pub const fn has_identity(&self) -> bool {
        self.identity.is_some()
    }

    /// The target peer, once resolution has completed.
    #[must_use]
    pub const fn target_peer(&self) -> Option<&PeerIdBytes> {
        self.target_peer.as_ref()
    }

    /// The single-use OAuth state, used to bind the browser callback.
    #[must_use]
    pub const fn oauth_state(&self) -> Option<&OAuthState> {
        self.oauth_state.as_ref()
    }

    /// Offers the configured providers: `Created -> ProviderSelection`.
    pub fn offer_providers(&mut self) -> Result<(), TransitionError> {
        self.forward(EnterpriseResolvePhase::Created, |session| {
            session.phase = EnterpriseResolvePhase::ProviderSelection;
            Ok(())
        })
    }

    /// Selects one provider and creates the single-use OAuth state:
    /// `ProviderSelection -> Authenticating`. The provider cannot change.
    pub fn select(
        &mut self,
        provider: EnterpriseProvider,
        random: &mut impl SecureRandom,
    ) -> Result<OAuthState, TransitionError> {
        self.forward(EnterpriseResolvePhase::ProviderSelection, |session| {
            let state = OAuthState::generate(random)?;
            session.provider = Some(provider);
            session.oauth_state = Some(state.clone());
            session.phase = EnterpriseResolvePhase::Authenticating;
            Ok(state)
        })
    }

    /// Applies a browser callback: validates the single-use state and
    /// stores the member identity for validation. A missing, mismatched
    /// or replayed state fails the session.
    pub fn callback(
        &mut self,
        state: &OAuthState,
        identity: MemberIdentity,
    ) -> Result<(), TransitionError> {
        self.forward(EnterpriseResolvePhase::Authenticating, |session| {
            let Some(mut stored) = session.oauth_state.take() else {
                session.phase = EnterpriseResolvePhase::Failed(EnterpriseFailure::InvalidState);
                return Err(TransitionError::InvalidState);
            };
            let matches = &stored == state;
            stored.zeroize();
            if !matches {
                session.phase = EnterpriseResolvePhase::Failed(EnterpriseFailure::InvalidState);
                return Err(TransitionError::InvalidState);
            }
            session.identity = Some(identity);
            Ok(())
        })
    }

    /// Validates membership: the identity is destroyed in both outcomes.
    /// `Authenticating -> Authenticated` or `Failed(UserRejected)`.
    pub fn validate_member(&mut self, valid: bool) -> Result<MemberAdmission, TransitionError> {
        self.forward(EnterpriseResolvePhase::Authenticating, |session| {
            let mut identity = session
                .identity
                .take()
                .ok_or(TransitionError::InvalidTransition)?;
            identity.zeroize();
            if valid {
                session.phase = EnterpriseResolvePhase::Authenticated;
                Ok(MemberAdmission::Admitted)
            } else {
                session.phase = EnterpriseResolvePhase::Failed(EnterpriseFailure::UserRejected);
                Ok(MemberAdmission::Rejected)
            }
        })
    }

    /// Starts the internal locator resolution: `Authenticated -> Resolving`.
    /// The session no longer carries any enterprise identity.
    pub fn begin_resolve(&mut self) -> Result<(), TransitionError> {
        self.forward(EnterpriseResolvePhase::Authenticated, |session| {
            debug_assert!(
                session.identity.is_none() && session.oauth_state.is_none(),
                "resolving never carries enterprise identity"
            );
            session.phase = EnterpriseResolvePhase::Resolving;
            Ok(())
        })
    }

    /// Records the resolved target: `Resolving -> Completed`.
    pub fn complete(&mut self, peer: PeerIdBytes) -> Result<(), TransitionError> {
        self.forward(EnterpriseResolvePhase::Resolving, |session| {
            session.target_peer = Some(peer);
            session.phase = EnterpriseResolvePhase::Completed;
            Ok(())
        })
    }

    /// Cancels the session from any active phase.
    pub fn cancel(&mut self) -> Result<(), TransitionError> {
        self.terminal(EnterpriseResolvePhase::Cancelled)
    }

    /// Expires the session from any active phase.
    pub fn expire(&mut self) -> Result<(), TransitionError> {
        self.terminal(EnterpriseResolvePhase::Expired)
    }

    /// Fails the session from any active phase.
    pub fn fail(&mut self, failure: EnterpriseFailure) -> Result<(), TransitionError> {
        self.terminal(EnterpriseResolvePhase::Failed(failure))
    }

    /// Marks the target locator unavailable from any active phase.
    pub fn unavailable(&mut self) -> Result<(), TransitionError> {
        self.terminal(EnterpriseResolvePhase::Unavailable)
    }

    fn forward<T>(
        &mut self,
        expected: EnterpriseResolvePhase,
        transition: impl FnOnce(&mut Self) -> Result<T, TransitionError>,
    ) -> Result<T, TransitionError> {
        if self.phase != expected {
            return Err(TransitionError::InvalidTransition);
        }
        transition(self)
    }

    fn terminal(&mut self, phase: EnterpriseResolvePhase) -> Result<(), TransitionError> {
        if self.phase.is_terminal() {
            return Err(TransitionError::Terminal);
        }
        self.phase = phase;
        Ok(())
    }
}

impl std::fmt::Debug for EnterpriseResolveSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnterpriseResolveSession")
            .field("request_id", &self.request_id)
            .field("phase", &self.phase)
            .field("provider", &self.provider)
            .finish()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        EnterpriseFailure, EnterpriseResolvePhase, EnterpriseResolveSession, MemberAdmission,
        MemberIdentity, OAuthState, RequestId, SESSION_LIFETIME, TransitionError,
    };
    use std::time::Duration;
    use yonder_core::{EnterpriseProvider, Locator, MonotonicTime, OsSecureRandom, PeerIdBytes};

    fn locator() -> Locator {
        Locator::new(0x12345).unwrap()
    }

    fn new_session() -> EnterpriseResolveSession {
        EnterpriseResolveSession::new(
            RequestId::new(7),
            locator(),
            MonotonicTime::from_elapsed(Duration::ZERO),
        )
    }

    fn identity() -> MemberIdentity {
        MemberIdentity::new(b"member-123").unwrap()
    }

    #[test]
    fn sessions_start_created_with_bounded_lifetime() {
        let now = MonotonicTime::from_elapsed(Duration::from_secs(100));
        let session = EnterpriseResolveSession::new(RequestId::new(1), locator(), now);
        assert_eq!(session.phase(), EnterpriseResolvePhase::Created);
        assert_eq!(session.request_id(), RequestId::new(1));
        assert_eq!(session.locator(), locator());
        assert_eq!(
            session.deadline(),
            now.checked_add(SESSION_LIFETIME).unwrap()
        );
        assert!(!session.is_terminal());
        assert!(!session.is_expired(now));
        assert!(session.is_expired(session.deadline()));
        assert!(session.provider().is_none());
        assert!(!session.has_identity());
    }

    #[test]
    fn oauth_state_is_created_only_after_provider_selection() {
        let mut session = new_session();
        assert!(session.oauth_state().is_none());
        session.offer_providers().unwrap();
        assert!(session.oauth_state().is_none());
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        assert_eq!(session.oauth_state(), Some(&state));
        assert_eq!(session.phase(), EnterpriseResolvePhase::Authenticating);
        assert_eq!(session.provider(), Some(EnterpriseProvider::WeCom));
    }

    #[test]
    fn provider_is_immutable_after_selection() {
        let mut session = new_session();
        session.offer_providers().unwrap();
        session
            .select(EnterpriseProvider::Feishu, &mut OsSecureRandom)
            .unwrap();
        assert!(matches!(
            session.select(EnterpriseProvider::WeCom, &mut OsSecureRandom),
            Err(TransitionError::InvalidTransition)
        ));
    }

    #[test]
    fn selection_requires_offered_providers() {
        let mut session = new_session();
        assert!(matches!(
            session.select(EnterpriseProvider::WeCom, &mut OsSecureRandom),
            Err(TransitionError::InvalidTransition)
        ));
    }

    #[test]
    fn state_is_single_use_and_replay_fails_the_session() {
        let mut session = new_session();
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        session.callback(&state, identity()).unwrap();
        assert_eq!(session.phase(), EnterpriseResolvePhase::Authenticating);
        assert!(session.has_identity());
        assert!(session.oauth_state().is_none());

        let replay = session.callback(&state, identity()).unwrap_err();
        assert!(matches!(replay, TransitionError::InvalidState));
        assert_eq!(
            session.phase(),
            EnterpriseResolvePhase::Failed(EnterpriseFailure::InvalidState)
        );
    }

    #[test]
    fn mismatched_state_fails_the_session() {
        let mut session = new_session();
        session.offer_providers().unwrap();
        session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        let wrong = OAuthState::generate(&mut OsSecureRandom).unwrap();
        let error = session.callback(&wrong, identity()).unwrap_err();
        assert!(matches!(error, TransitionError::InvalidState));
        assert_eq!(
            session.phase(),
            EnterpriseResolvePhase::Failed(EnterpriseFailure::InvalidState)
        );
        assert!(!session.has_identity());
    }

    #[test]
    fn member_validation_destroys_identity_and_admits_or_rejects() {
        let mut session = new_session();
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        session.callback(&state, identity()).unwrap();
        assert!(session.has_identity());

        assert_eq!(
            session.validate_member(true).unwrap(),
            MemberAdmission::Admitted
        );
        assert!(!session.has_identity());
        assert_eq!(session.phase(), EnterpriseResolvePhase::Authenticated);

        let mut rejected = new_session();
        rejected.offer_providers().unwrap();
        let state = rejected
            .select(EnterpriseProvider::Feishu, &mut OsSecureRandom)
            .unwrap();
        rejected.callback(&state, identity()).unwrap();
        assert_eq!(
            rejected.validate_member(false).unwrap(),
            MemberAdmission::Rejected
        );
        assert!(!rejected.has_identity());
        assert_eq!(
            rejected.phase(),
            EnterpriseResolvePhase::Failed(EnterpriseFailure::UserRejected)
        );
    }

    #[test]
    fn resolving_never_carries_enterprise_identity() {
        let mut session = new_session();
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        session.callback(&state, identity()).unwrap();
        session.validate_member(true).unwrap();
        assert!(!session.has_identity());
        session.begin_resolve().unwrap();
        assert_eq!(session.phase(), EnterpriseResolvePhase::Resolving);
        assert!(!session.has_identity());
        assert!(session.oauth_state().is_none());
    }

    #[test]
    fn completed_sessions_record_the_target_peer() {
        let mut session = new_session();
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        session.callback(&state, identity()).unwrap();
        session.validate_member(true).unwrap();
        session.begin_resolve().unwrap();
        assert!(matches!(
            session.complete(PeerIdBytes::new(&[9, 8, 7]).unwrap()),
            Ok(())
        ));
        assert_eq!(session.phase(), EnterpriseResolvePhase::Completed);
        assert_eq!(
            session.target_peer(),
            Some(&PeerIdBytes::new(&[9, 8, 7]).unwrap())
        );
        assert!(session.is_terminal());
    }

    #[test]
    fn every_active_phase_reaches_every_terminal_failure() {
        for phase in [
            EnterpriseResolvePhase::Created,
            EnterpriseResolvePhase::ProviderSelection,
            EnterpriseResolvePhase::Authenticating,
            EnterpriseResolvePhase::Authenticated,
            EnterpriseResolvePhase::Resolving,
        ] {
            let mut session = new_session();
            session.phase_for_test(phase);
            session.cancel().unwrap();
            assert_eq!(session.phase(), EnterpriseResolvePhase::Cancelled);
            assert!(matches!(session.cancel(), Err(TransitionError::Terminal)));

            let mut session = new_session();
            session.phase_for_test(phase);
            session.expire().unwrap();
            assert_eq!(session.phase(), EnterpriseResolvePhase::Expired);
            assert!(matches!(session.expire(), Err(TransitionError::Terminal)));

            let mut session = new_session();
            session.phase_for_test(phase);
            session.fail(EnterpriseFailure::Platform).unwrap();
            assert_eq!(
                session.phase(),
                EnterpriseResolvePhase::Failed(EnterpriseFailure::Platform)
            );
            assert!(matches!(
                session.fail(EnterpriseFailure::Platform),
                Err(TransitionError::Terminal)
            ));

            let mut session = new_session();
            session.phase_for_test(phase);
            session.unavailable().unwrap();
            assert_eq!(session.phase(), EnterpriseResolvePhase::Unavailable);
            assert!(matches!(
                session.unavailable(),
                Err(TransitionError::Terminal)
            ));
        }
    }

    #[test]
    fn forward_transitions_require_the_exact_phase() {
        let mut session = new_session();
        assert!(matches!(
            session.complete(PeerIdBytes::new(&[1]).unwrap()),
            Err(TransitionError::InvalidTransition)
        ));
        assert!(matches!(
            session.validate_member(true),
            Err(TransitionError::InvalidTransition)
        ));
        assert!(matches!(
            session.begin_resolve(),
            Err(TransitionError::InvalidTransition)
        ));
        session.cancel().unwrap();
        assert!(matches!(
            session.offer_providers(),
            Err(TransitionError::InvalidTransition)
        ));
    }

    #[test]
    fn member_identities_are_bounded() {
        assert!(MemberIdentity::new(&[]).is_err());
        assert!(MemberIdentity::new(&[0_u8; MemberIdentity::MAX_LEN + 1]).is_err());
        assert_eq!(MemberIdentity::new(b"abc").unwrap().as_bytes(), &b"abc"[..]);
    }

    #[test]
    fn debug_never_leaks_identity_state_or_peer() {
        let mut session = new_session();
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        session.callback(&state, identity()).unwrap();
        session.validate_member(true).unwrap();
        session.begin_resolve().unwrap();
        session
            .complete(PeerIdBytes::new(&[9, 8, 7]).unwrap())
            .unwrap();

        let debug = format!("{session:?}");
        assert!(debug.contains("request_id"));
        assert!(debug.contains("Completed"));
        assert!(!debug.contains("member-123"));
        assert!(!debug.contains("9, 8, 7"));
        let state_debug = format!("{state:?}");
        assert!(state_debug.contains("redacted"));
    }

    impl EnterpriseResolveSession {
        fn phase_for_test(&mut self, phase: EnterpriseResolvePhase) {
            self.phase = phase;
        }
    }
}
