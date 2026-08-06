//! Enterprise callback session machinery: the bounded single-use
//! transaction registry and the callback session handler (design
//! sections 8, 10 and 11). The HTTPS surface lives in `callback`.

use crate::callback::{CallbackHandler, CallbackResult};
use crate::session::{
    EnterpriseFailure, EnterpriseResolveSession, MemberAdmission, OAuthState, RequestId,
};
use crate::verifier::{ExchangeTransport, VerifyError, verify_member};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::oneshot;
use yonder_core::rate::{DirectRateLimiter, RateLimit};
use yonder_core::{EnterpriseProvider, MonotonicClock, MonotonicTime};

#[derive(Debug)]
pub struct CallbackEntry {
    session: Arc<Mutex<EnterpriseResolveSession>>,
    outcome: oneshot::Sender<CallbackResult>,
    request_id: RequestId,
    deadline: MonotonicTime,
}

impl CallbackEntry {
    /// Registers a transaction whose session has just created its
    /// single-use state. The deadline is copied from the session so the
    /// registry can expire transactions without locking sessions.
    #[must_use]
    pub fn new(
        session: Arc<Mutex<EnterpriseResolveSession>>,
        outcome: oneshot::Sender<CallbackResult>,
        request_id: RequestId,
        deadline: MonotonicTime,
    ) -> Self {
        Self {
            session,
            outcome,
            request_id,
            deadline,
        }
    }

    /// The shared session of this transaction.
    #[must_use]
    pub fn session(&self) -> Arc<Mutex<EnterpriseResolveSession>> {
        Arc::clone(&self.session)
    }

    /// The redacted request identifier used in logs.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// The session deadline, used for expiry.
    #[must_use]
    pub const fn deadline(&self) -> MonotonicTime {
        self.deadline
    }

    /// Consumes the completion signal.
    #[must_use]
    pub fn into_outcome(self) -> oneshot::Sender<CallbackResult> {
        self.outcome
    }
}

/// Bounded in-memory registry of authenticating callback transactions
/// keyed by their single-use OAuth state (design sections 8 and 11).
///
/// Transactions are never persisted: a relay restart drops all of them.
/// Each state can be taken at most once, so callback replays are
/// impossible; the capacity bound fails inserts closed. Expired
/// transactions are swept lazily using the copied deadlines, without
/// ever locking a session while the registry lock is held.
#[derive(Debug)]
pub struct CallbackRegistry {
    transactions: Mutex<HashMap<OAuthState, CallbackEntry>>,
    capacity: usize,
}

impl CallbackRegistry {
    /// The bounded transaction capacity of one relay process.
    pub const DEFAULT_CAPACITY: usize = 64;

    /// Creates a registry with the default transaction capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// Creates a registry with an explicit transaction capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            transactions: Mutex::new(HashMap::with_capacity(capacity)),
            capacity,
        }
    }

    /// Registers one transaction under its single-use state, after
    /// sweeping expired entries. The session's lock must not be held.
    pub fn insert(
        &self,
        state: OAuthState,
        entry: CallbackEntry,
        now: MonotonicTime,
    ) -> Result<(), CallbackRegistryError> {
        let mut transactions = self.transactions.lock().unwrap();
        sweep(&mut transactions, now);
        if transactions.len() >= self.capacity {
            return Err(CallbackRegistryError::Capacity);
        }
        if transactions.insert(state, entry).is_some() {
            return Err(CallbackRegistryError::DuplicateState);
        }
        Ok(())
    }

    /// Takes the transaction for one state, consuming the single-use
    /// entry. Any second callback with the same state finds nothing.
    pub fn take(&self, state: &OAuthState, now: MonotonicTime) -> Option<CallbackEntry> {
        let mut transactions = self.transactions.lock().unwrap();
        sweep(&mut transactions, now);
        transactions.remove(state)
    }

    /// Removes the transaction of one state without consuming it,
    /// used when the connect substream dies before any callback.
    pub fn remove(&self, state: &OAuthState) -> bool {
        self.transactions.lock().unwrap().remove(state).is_some()
    }

    /// The number of live transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.lock().unwrap().len()
    }

    /// Whether no transactions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CallbackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn sweep(transactions: &mut HashMap<OAuthState, CallbackEntry>, now: MonotonicTime) {
    transactions.retain(|_, entry| entry.deadline() > now);
}

/// Transaction registry failures.
#[derive(Debug, Error)]
pub enum CallbackRegistryError {
    #[error("the enterprise transaction capacity is exhausted")]
    Capacity,
    #[error("the enterprise transaction state is already registered")]
    DuplicateState,
}

/// Bound on the per-source callback rate limiter table.
pub const CALLBACK_SOURCE_CAPACITY: usize = 1024;
/// How long a source limiter stays in the table after its last callback.
pub const CALLBACK_SOURCE_IDLE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Handles validated callbacks against the shared transaction registry.
///
/// Owns the single-use state lookup, the bounded provider verification,
/// the session transitions and the redacted logging (design section 10):
/// only the request id, platform, phase and redacted result are logged.
/// Callback sources are rate limited per IP address using the shared
/// authentication limiter; the source address is never logged.
pub struct CallbackSessionHandler<C: MonotonicClock, T: ExchangeTransport> {
    registry: Arc<CallbackRegistry>,
    credentials: Arc<crate::provider::ProviderCredentials>,
    transport: T,
    clock: C,
    sources: Mutex<HashMap<IpAddr, (DirectRateLimiter, MonotonicTime)>>,
}

impl<C: MonotonicClock, T: ExchangeTransport> CallbackSessionHandler<C, T> {
    /// Creates the callback handler over the shared registry and the
    /// startup-loaded provider credentials.
    #[must_use]
    pub fn new(
        registry: Arc<CallbackRegistry>,
        credentials: Arc<crate::provider::ProviderCredentials>,
        transport: T,
        clock: C,
    ) -> Self {
        Self {
            registry,
            credentials,
            transport,
            clock,
            sources: Mutex::new(HashMap::with_capacity(64)),
        }
    }

    fn check_source(&self, source: IpAddr, now: MonotonicTime) -> bool {
        let mut sources = self.sources.lock().unwrap();
        sources.retain(|_, (_, last_seen)| {
            now.duration_since(*last_seen)
                .is_none_or(|age| age < CALLBACK_SOURCE_IDLE)
        });
        if let Some((limiter, last_seen)) = sources.get_mut(&source) {
            *last_seen = now;
            return limiter.check();
        }
        if sources.len() >= CALLBACK_SOURCE_CAPACITY {
            return false;
        }
        let limiter = DirectRateLimiter::new(RateLimit::authentication());
        let allowed = limiter.check();
        sources.insert(source, (limiter, now));
        allowed
    }
}

/// Decodes the provider-echoed lowercase-hex state.
fn decode_state(state: &str) -> Option<OAuthState> {
    let bytes = data_encoding::HEXLOWER.decode(state.as_bytes()).ok()?;
    OAuthState::from_bytes(&bytes).ok()
}

impl<C, T> CallbackHandler for CallbackSessionHandler<C, T>
where
    C: MonotonicClock + Send + Sync,
    T: ExchangeTransport + Send + Sync,
{
    fn handle<'a>(
        &'a self,
        provider: EnterpriseProvider,
        code: &'a str,
        state: &'a str,
        source: IpAddr,
    ) -> std::pin::Pin<Box<dyn Future<Output = CallbackResult> + Send + 'a>> {
        let registry = Arc::clone(&self.registry);
        let credentials = Arc::clone(&self.credentials);
        Box::pin(async move {
            let now = self.clock.now();
            if !self.check_source(source, now) {
                tracing::info!(
                    event = "enterprise_callback_rejected",
                    platform = provider.as_str(),
                    phase = "callback",
                    result = "rate-limited",
                    "enterprise callback rate limited"
                );
                return CallbackResult::Limited;
            }
            let Some(state) = decode_state(state) else {
                tracing::info!(
                    event = "enterprise_callback_rejected",
                    platform = provider.as_str(),
                    phase = "callback",
                    result = "malformed-state",
                    "enterprise callback state malformed"
                );
                return CallbackResult::InvalidState;
            };
            let Some(entry) = registry.take(&state, now) else {
                tracing::info!(
                    event = "enterprise_callback_rejected",
                    platform = provider.as_str(),
                    phase = "callback",
                    result = "unknown-state",
                    "enterprise callback state unknown"
                );
                return CallbackResult::InvalidState;
            };
            let request_id = entry.request_id();
            let outcome = match verify_member(&self.transport, provider, code, &credentials).await {
                Ok(identity) => {
                    let session = entry.session();
                    let mut guard = session.lock().unwrap();
                    if guard.callback(&state, identity).is_err() {
                        CallbackResult::InvalidState
                    } else if matches!(guard.validate_member(true), Ok(MemberAdmission::Admitted)) {
                        CallbackResult::Admitted
                    } else {
                        CallbackResult::Rejected
                    }
                }
                Err(VerifyError::InvalidCode) => {
                    let session = entry.session();
                    let _ = session
                        .lock()
                        .unwrap()
                        .fail(EnterpriseFailure::InvalidState);
                    CallbackResult::InvalidState
                }
                Err(VerifyError::Rejected) => {
                    let session = entry.session();
                    let _ = session
                        .lock()
                        .unwrap()
                        .fail(EnterpriseFailure::UserRejected);
                    CallbackResult::Rejected
                }
                Err(VerifyError::Platform | VerifyError::ResponseTooLarge) => {
                    let session = entry.session();
                    let _ = session.lock().unwrap().fail(EnterpriseFailure::Platform);
                    CallbackResult::Platform
                }
            };
            tracing::info!(
                event = "enterprise_callback",
                request_id = %request_id,
                platform = provider.as_str(),
                phase = "callback",
                result = outcome.as_str(),
                "enterprise callback completed"
            );
            let _ = entry.into_outcome().send(outcome);
            outcome
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CallbackEntry, CallbackRegistry, CallbackRegistryError, CallbackSessionHandler,
        decode_state,
    };
    use crate::callback::CallbackHandler as _;
    use crate::callback::CallbackResult;
    use crate::provider::{ProviderCredentials, ProviderField, SecretText, WeComCredentials};
    use crate::session::{EnterpriseResolvePhase, EnterpriseResolveSession, OAuthState, RequestId};
    use std::collections::VecDeque;
    use std::io;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::oneshot;
    use url::Url;
    use yonder_core::{EnterpriseProvider, Locator, MonotonicClock, MonotonicTime, OsSecureRandom};

    fn locator() -> Locator {
        Locator::new(0x12345).unwrap()
    }

    fn now() -> MonotonicTime {
        MonotonicTime::from_elapsed(std::time::Duration::ZERO)
    }

    fn authenticating_session(
        now: MonotonicTime,
    ) -> (Arc<StdMutex<EnterpriseResolveSession>>, OAuthState) {
        let mut session = EnterpriseResolveSession::new(RequestId::new(7), locator(), now);
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        (Arc::new(StdMutex::new(session)), state)
    }

    fn entry(
        session: Arc<StdMutex<EnterpriseResolveSession>>,
        now: MonotonicTime,
    ) -> (CallbackEntry, oneshot::Receiver<CallbackResult>) {
        let (outcome_tx, outcome_rx) = oneshot::channel();
        let entry = CallbackEntry::new(
            session,
            outcome_tx,
            RequestId::new(7),
            now.checked_add(crate::session::SESSION_LIFETIME).unwrap(),
        );
        (entry, outcome_rx)
    }

    fn wecom_credentials() -> ProviderCredentials {
        let wecom = WeComCredentials {
            corp_id: SecretText::new("ww1234567890abcdef".into(), ProviderField::CorpId).unwrap(),
            agent_id: 7,
            app_secret: SecretText::new("s3cret".into(), ProviderField::AppSecret).unwrap(),
        };
        ProviderCredentials::from_credentials(Some(wecom), None)
    }

    struct FakeExchange {
        responses: StdMutex<VecDeque<Result<Vec<u8>, io::Error>>>,
    }

    impl FakeExchange {
        fn new(responses: Vec<Result<Vec<u8>, io::Error>>) -> Self {
            Self {
                responses: StdMutex::new(responses.into()),
            }
        }
    }

    fn ok(response: &str) -> Result<Vec<u8>, io::Error> {
        Ok(response.as_bytes().to_vec())
    }

    impl crate::verifier::ExchangeTransport for FakeExchange {
        fn get(
            &self,
            _url: &Url,
            _bearer: Option<&str>,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            let response = self.responses.lock().unwrap().pop_front();
            async move {
                response.unwrap_or_else(|| Err(io::Error::other("unexpected provider request")))
            }
        }

        fn post_json(
            &self,
            _url: &Url,
            _body: &str,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            let response = self.responses.lock().unwrap().pop_front();
            async move {
                response.unwrap_or_else(|| Err(io::Error::other("unexpected provider request")))
            }
        }
    }

    struct FixedClock(MonotonicTime);

    impl MonotonicClock for FixedClock {
        fn now(&self) -> MonotonicTime {
            self.0
        }
    }

    fn handler_with(exchange: FakeExchange) -> CallbackSessionHandler<FixedClock, FakeExchange> {
        CallbackSessionHandler::new(
            Arc::new(CallbackRegistry::new()),
            Arc::new(wecom_credentials()),
            exchange,
            FixedClock(now()),
        )
    }

    #[test]
    fn registry_enforces_single_use_capacity_and_expiry() {
        let registry = CallbackRegistry::new();
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, _outcome) = entry(session, started);
        registry
            .insert(state.clone(), callback_entry, started)
            .unwrap();
        assert_eq!(registry.len(), 1);

        // The single-use take consumes the entry; a replay finds nothing.
        let taken = registry.take(&state, started).unwrap();
        assert_eq!(taken.request_id(), RequestId::new(7));
        assert!(registry.take(&state, started).is_none());
        assert!(registry.is_empty());

        // A duplicate insert of the same state is refused.
        let (session, state) = authenticating_session(started);
        let (first, _) = entry(session.clone(), started);
        let (second, _) = entry(session, started);
        registry.insert(state.clone(), first, started).unwrap();
        assert!(matches!(
            registry.insert(state.clone(), second, started),
            Err(CallbackRegistryError::DuplicateState)
        ));

        // Capacity exhaustion fails closed.
        let small = CallbackRegistry::with_capacity(1);
        let (session, state) = authenticating_session(started);
        let (callback_entry, _) = entry(session, started);
        small
            .insert(state.clone(), callback_entry, started)
            .unwrap();
        let (session, other_state) = authenticating_session(started);
        let (callback_entry, _) = entry(session, started);
        assert!(matches!(
            small.insert(other_state, callback_entry, started),
            Err(CallbackRegistryError::Capacity)
        ));

        // Expired transactions are swept on the next insert or take.
        let expired = now().checked_add(crate::session::SESSION_LIFETIME).unwrap();
        let (session, state) = authenticating_session(now());
        let (callback_entry, _) = entry(session, now());
        registry
            .insert(state.clone(), callback_entry, now())
            .unwrap();
        assert!(registry.take(&state, expired).is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn state_decoding_is_strict_lowercase_hex_of_32_bytes() {
        let (_, state) = authenticating_session(now());
        let encoded = data_encoding::HEXLOWER.encode(state.as_bytes());
        assert_eq!(decode_state(&encoded), Some(state));
        assert_eq!(decode_state(&encoded.to_uppercase()), None);
        assert_eq!(decode_state("xyz"), None);
        assert_eq!(decode_state(""), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_admits_active_members_and_completes_the_transaction() {
        let exchange = FakeExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san","status":1}"#),
        ]);
        let handler = handler_with(exchange);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome_rx) = entry(session.clone(), started);
        handler
            .registry
            .insert(state.clone(), callback_entry, started)
            .unwrap();
        let encoded = data_encoding::HEXLOWER.encode(state.as_bytes());
        let result = handler
            .handle(
                EnterpriseProvider::WeCom,
                "auth-code-1",
                &encoded,
                "203.0.113.9".parse().unwrap(),
            )
            .await;
        assert_eq!(result, CallbackResult::Admitted);
        assert_eq!(outcome_rx.await, Ok(CallbackResult::Admitted));
        assert_eq!(
            session.lock().unwrap().phase(),
            EnterpriseResolvePhase::Authenticated
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_rejects_external_users_and_completes_the_transaction() {
        let exchange = FakeExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","external_userid":"wo_12345"}"#),
        ]);
        let handler = handler_with(exchange);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome_rx) = entry(session.clone(), started);
        handler
            .registry
            .insert(state.clone(), callback_entry, started)
            .unwrap();
        let encoded = data_encoding::HEXLOWER.encode(state.as_bytes());
        let result = handler
            .handle(
                EnterpriseProvider::WeCom,
                "auth-code-1",
                &encoded,
                "203.0.113.9".parse().unwrap(),
            )
            .await;
        assert_eq!(result, CallbackResult::Rejected);
        assert_eq!(outcome_rx.await, Ok(CallbackResult::Rejected));
        assert!(matches!(
            session.lock().unwrap().phase(),
            EnterpriseResolvePhase::Failed(_)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_fails_closed_on_platform_errors() {
        let exchange = FakeExchange::new(vec![Err(io::Error::other("network unreachable"))]);
        let handler = handler_with(exchange);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome_rx) = entry(session.clone(), started);
        handler
            .registry
            .insert(state.clone(), callback_entry, started)
            .unwrap();
        let encoded = data_encoding::HEXLOWER.encode(state.as_bytes());
        let result = handler
            .handle(
                EnterpriseProvider::WeCom,
                "auth-code-1",
                &encoded,
                "203.0.113.9".parse().unwrap(),
            )
            .await;
        assert_eq!(result, CallbackResult::Platform);
        assert_eq!(outcome_rx.await, Ok(CallbackResult::Platform));
        assert!(matches!(
            session.lock().unwrap().phase(),
            EnterpriseResolvePhase::Failed(_)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_rejects_unknown_and_replayed_states() {
        let exchange = FakeExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san","status":1}"#),
        ]);
        let handler = handler_with(exchange);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, _outcome) = entry(session, started);
        handler
            .registry
            .insert(state.clone(), callback_entry, started)
            .unwrap();
        let encoded = data_encoding::HEXLOWER.encode(state.as_bytes());
        // An unknown state finds no transaction.
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    "auth-code-1",
                    "0f00000000000000000000000000000000000000000000000000000000000000",
                    "203.0.113.9".parse().unwrap(),
                )
                .await,
            CallbackResult::InvalidState
        );
        // The real state is consumed exactly once.
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    "auth-code-1",
                    &encoded,
                    "203.0.113.9".parse().unwrap(),
                )
                .await,
            CallbackResult::Admitted
        );
        // The replay of the consumed state finds nothing.
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    "auth-code-1",
                    &encoded,
                    "203.0.113.9".parse().unwrap(),
                )
                .await,
            CallbackResult::InvalidState
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_rate_limits_sources_with_bounded_table() {
        let exchange = FakeExchange::new(vec![Err(io::Error::other("network unreachable"))]);
        let handler = handler_with(exchange);
        let source: IpAddr = "203.0.113.9".parse().unwrap();
        // The authentication limiter allows a burst of 4, then fails.
        let mut results = Vec::new();
        for _ in 0..6 {
            results.push(
                handler
                    .handle(
                        EnterpriseProvider::WeCom,
                        "auth-code-1",
                        "0f00000000000000000000000000000000000000000000000000000000000000",
                        source,
                    )
                    .await,
            );
        }
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == CallbackResult::InvalidState)
                .count(),
            4
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == CallbackResult::Limited)
                .count(),
            2
        );
    }
}
