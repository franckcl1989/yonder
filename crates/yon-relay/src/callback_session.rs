//! Enterprise callback session machinery: the bounded single-use
//! transaction registry and the callback session handler (design
//! sections 8, 10 and 11). The HTTPS surface lives in `callback`.

use crate::callback::{CallbackAuthorization, CallbackHandler, CallbackResult};
use crate::session::{
    EnterpriseFailure, EnterpriseResolveSession, MemberAdmission, OAuthState, RequestId,
};
use crate::verifier::{ExchangeTransport, VerifyError, verify_member};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use yonder_core::{EnterpriseProvider, MonotonicClock, MonotonicTime};

/// A callback result and the exclusively-owned session returned to the
/// resolve task after the relay owner commits the completion.
#[derive(Debug)]
pub struct CallbackCompletion {
    result: CallbackResult,
    session: EnterpriseResolveSession,
}

impl CallbackCompletion {
    #[must_use]
    pub const fn result(&self) -> CallbackResult {
        self.result
    }

    #[must_use]
    pub fn into_session(self) -> EnterpriseResolveSession {
        self.session
    }
}

#[derive(Debug)]
pub struct CallbackEntry {
    session: Box<EnterpriseResolveSession>,
    outcome: oneshot::Sender<CallbackCompletion>,
    cancelled: oneshot::Receiver<()>,
    request_id: RequestId,
    deadline: MonotonicTime,
}

impl CallbackEntry {
    /// Registers a transaction whose session has just created its
    /// single-use state. The deadline is copied from the session so the
    /// registry can expire transactions without locking sessions.
    #[must_use]
    pub fn new(
        session: EnterpriseResolveSession,
        outcome: oneshot::Sender<CallbackCompletion>,
        cancelled: oneshot::Receiver<()>,
        request_id: RequestId,
        deadline: MonotonicTime,
    ) -> Self {
        Self {
            session: Box::new(session),
            outcome,
            cancelled,
            request_id,
            deadline,
        }
    }

    /// The exclusively-owned session of this transaction.
    #[must_use]
    pub fn session(&self) -> &EnterpriseResolveSession {
        self.session.as_ref()
    }

    #[must_use]
    pub fn session_mut(&mut self) -> &mut EnterpriseResolveSession {
        self.session.as_mut()
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

    /// Returns the session to the resolve task and consumes the entry.
    pub fn complete(self, result: CallbackResult) {
        let completion = CallbackCompletion {
            result,
            session: *self.session,
        };
        let _ = self.outcome.send(completion);
    }

    fn cancellation_requested(&mut self) -> bool {
        !matches!(
            self.cancelled.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        )
    }
}

/// Bounded in-memory registry of authenticating callback transactions
/// keyed by their single-use OAuth state (design sections 8 and 11).
///
/// Transactions are never persisted: a relay restart drops all of them.
/// Each state can be taken at most once, so callback replays are
/// impossible; the capacity bound fails inserts closed. Expired
/// transactions are swept lazily using the copied deadlines. This type
/// contains no synchronization: the relay event loop is its sole owner.
#[derive(Debug)]
pub struct CallbackRegistry {
    transactions: HashMap<OAuthState, CallbackEntry>,
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
            transactions: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    /// Registers one transaction under its single-use state, after
    /// sweeping expired entries. The relay event loop serializes calls.
    pub fn insert(
        &mut self,
        state: OAuthState,
        entry: CallbackEntry,
        now: MonotonicTime,
    ) -> Result<(), CallbackRegistryError> {
        sweep(&mut self.transactions, now);
        if self.transactions.contains_key(&state) {
            return Err(CallbackRegistryError::DuplicateState);
        }
        if self.transactions.len() >= self.capacity {
            return Err(CallbackRegistryError::Capacity);
        }
        let replaced = self.transactions.insert(state, entry);
        debug_assert!(
            replaced.is_none(),
            "the owner serialized the duplicate check"
        );
        Ok(())
    }

    /// Takes the transaction for one state, consuming the single-use
    /// entry. Any second callback with the same state finds nothing.
    pub fn take(&mut self, state: &OAuthState, now: MonotonicTime) -> Option<CallbackEntry> {
        sweep(&mut self.transactions, now);
        self.transactions.remove(state)
    }

    /// Removes the transaction of one state without consuming it,
    /// used when the connect substream dies before any callback.
    pub fn remove(&mut self, state: &OAuthState) -> Option<CallbackEntry> {
        self.transactions.remove(state)
    }

    /// The number of live transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.len()
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

/// Owner-side messages accepted from the bounded HTTPS callback channel.
pub enum CallbackRegistryRequest {
    Take {
        state: OAuthState,
        now: MonotonicTime,
        response: oneshot::Sender<Option<CallbackEntry>>,
    },
    Complete {
        entry: CallbackEntry,
        result: CallbackResult,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<CallbackResult>,
    },
}

/// Applies one HTTPS callback request inside the relay event-loop owner.
pub fn handle_callback_registry_request(
    registry: &mut CallbackRegistry,
    request: CallbackRegistryRequest,
) {
    match request {
        CallbackRegistryRequest::Take {
            state,
            now,
            response,
        } => {
            let entry = registry.take(&state, now);
            let _ = response.send(entry);
        }
        CallbackRegistryRequest::Complete {
            mut entry,
            mut result,
            deadline,
            response,
        } => {
            if entry.cancellation_requested() {
                let _ = entry.session_mut().cancel();
                result = CallbackResult::InvalidState;
            } else if tokio::time::Instant::now() >= deadline {
                let _ = entry.session_mut().fail(EnterpriseFailure::Platform);
                result = CallbackResult::Platform;
            }
            entry.complete(result);
            let _ = response.send(result);
        }
    }
}

/// Handles validated callbacks through the relay-owned transaction registry.
///
/// Owns the single-use state lookup, the bounded provider verification,
/// the session transitions and the redacted logging (design section 10):
/// only the request id, platform, phase and redacted result are logged.
/// The public HTTPS listener supplies the connection concurrency bound;
/// the 256-bit single-use state and the 64-entry transaction bound are
/// the callback abuse controls. There is deliberately no per-IP member
/// limiter because many legitimate employees share one corporate NAT.
pub struct CallbackSessionHandler<C: MonotonicClock, T: ExchangeTransport> {
    requests: mpsc::Sender<CallbackRegistryRequest>,
    credentials: Arc<crate::provider::ProviderCredentials>,
    transport: T,
    clock: C,
}

impl<C: MonotonicClock, T: ExchangeTransport> CallbackSessionHandler<C, T> {
    /// Creates the callback handler over its bounded owner channel and
    /// the startup-loaded provider credentials.
    #[must_use]
    pub fn new(
        requests: mpsc::Sender<CallbackRegistryRequest>,
        credentials: Arc<crate::provider::ProviderCredentials>,
        transport: T,
        clock: C,
    ) -> Self {
        Self {
            requests,
            credentials,
            transport,
            clock,
        }
    }
}

/// Decodes the canonical 256-bit URL-safe Base64 state without padding.
fn decode_state(state: &str) -> Option<OAuthState> {
    if state.len() != 43 {
        return None;
    }
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(state.as_bytes())
        .ok()?;
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
        authorization: CallbackAuthorization<'a>,
        state: &'a str,
        _source: IpAddr,
        deadline: tokio::time::Instant,
    ) -> std::pin::Pin<Box<dyn Future<Output = CallbackResult> + Send + 'a>> {
        let credentials = Arc::clone(&self.credentials);
        Box::pin(async move {
            let now = self.clock.now();
            let Some(state) = decode_state(state) else {
                tracing::debug!(
                    event = "enterprise_callback_rejected",
                    platform = provider.as_str(),
                    phase = "callback",
                    result = "malformed-state",
                    "enterprise callback state malformed"
                );
                return CallbackResult::InvalidState;
            };

            let (response, received) = oneshot::channel();
            let request = CallbackRegistryRequest::Take {
                state: state.clone(),
                now,
                response,
            };
            if tokio::time::timeout_at(deadline, self.requests.send(request))
                .await
                .is_err()
            {
                return CallbackResult::Platform;
            }
            let entry = match tokio::time::timeout_at(deadline, received).await {
                Ok(Ok(Some(entry))) => entry,
                Ok(Ok(None)) => {
                    tracing::debug!(
                        event = "enterprise_callback_rejected",
                        platform = provider.as_str(),
                        phase = "callback",
                        result = "unknown-state",
                        "enterprise callback state unknown"
                    );
                    return CallbackResult::InvalidState;
                }
                Ok(Err(_)) | Err(_) => return CallbackResult::Platform,
            };
            let mut entry = entry;
            let request_id = entry.request_id();

            // A callback route is bound to the provider selected by the
            // resolve session. A mismatched route consumes the single-use
            // state and fails closed without contacting either provider.
            if entry.session().provider() != Some(provider) {
                let _ = entry.session_mut().fail(EnterpriseFailure::InvalidState);
                finish_entry(
                    &self.requests,
                    entry,
                    CallbackResult::InvalidState,
                    deadline,
                )
                .await;
                return CallbackResult::InvalidState;
            }

            let outcome = match authorization {
                CallbackAuthorization::Code(code) => {
                    let verification = verify_member(&self.transport, provider, code, &credentials);
                    tokio::pin!(verification);
                    tokio::select! {
                        result = &mut verification => match result {
                            Ok(identity) => {
                                let session = entry.session_mut();
                                if session.callback(&state, identity).is_err() {
                                    CallbackResult::InvalidState
                                } else if matches!(
                                    session.validate_member(true),
                                    Ok(MemberAdmission::Admitted)
                                ) {
                                    CallbackResult::Admitted
                                } else {
                                    CallbackResult::Rejected
                                }
                            }
                            Err(VerifyError::InvalidCode) => {
                                let _ = entry
                                    .session_mut()
                                    .fail(EnterpriseFailure::InvalidState);
                                CallbackResult::InvalidState
                            }
                            Err(VerifyError::Rejected) => {
                                let _ = entry
                                    .session_mut()
                                    .fail(EnterpriseFailure::UserRejected);
                                CallbackResult::Rejected
                            }
                            Err(VerifyError::Platform | VerifyError::ResponseTooLarge) => {
                                let _ = entry.session_mut().fail(EnterpriseFailure::Platform);
                                CallbackResult::Platform
                            }
                        },
                        _ = &mut entry.cancelled => {
                            let _ = entry.session_mut().cancel();
                            CallbackResult::InvalidState
                        }
                        () = tokio::time::sleep_until(deadline) => {
                            let _ = entry.session_mut().fail(EnterpriseFailure::Platform);
                            CallbackResult::Platform
                        }
                    }
                }
                CallbackAuthorization::Denied => {
                    let _ = entry.session_mut().fail(EnterpriseFailure::UserRejected);
                    CallbackResult::Rejected
                }
                CallbackAuthorization::ProviderFailed => {
                    let _ = entry.session_mut().fail(EnterpriseFailure::Platform);
                    CallbackResult::Platform
                }
            };

            let outcome = finish_entry(&self.requests, entry, outcome, deadline).await;
            tracing::info!(
                event = "enterprise_callback",
                request_id = %request_id,
                platform = provider.as_str(),
                phase = "callback",
                result = outcome.as_str(),
                "enterprise callback completed"
            );
            outcome
        })
    }
}

async fn finish_entry(
    requests: &mpsc::Sender<CallbackRegistryRequest>,
    mut entry: CallbackEntry,
    result: CallbackResult,
    deadline: tokio::time::Instant,
) -> CallbackResult {
    let permit = match tokio::time::timeout_at(deadline, requests.reserve()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) | Err(_) => {
            let _ = entry.session_mut().fail(EnterpriseFailure::Platform);
            entry.complete(CallbackResult::Platform);
            return CallbackResult::Platform;
        }
    };
    let (response, received) = oneshot::channel();
    permit.send(CallbackRegistryRequest::Complete {
        entry,
        result,
        deadline,
        response,
    });
    match tokio::time::timeout_at(deadline, received).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => CallbackResult::Platform,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CallbackCompletion, CallbackEntry, CallbackRegistry, CallbackRegistryError,
        CallbackRegistryRequest, CallbackSessionHandler, decode_state, finish_entry,
        handle_callback_registry_request,
    };
    use crate::callback::{CallbackAuthorization, CallbackHandler as _, CallbackResult};
    use crate::provider::{ProviderCredentials, ProviderField, SecretText, WeComCredentials};
    use crate::session::{
        EnterpriseFailure, EnterpriseResolvePhase, EnterpriseResolveSession, OAuthState, RequestId,
    };
    use std::collections::VecDeque;
    use std::io;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::{mpsc, oneshot};
    use url::Url;
    use yonder_core::{EnterpriseProvider, Locator, MonotonicClock, MonotonicTime, OsSecureRandom};

    fn locator() -> Locator {
        Locator::new(0x12345).unwrap()
    }

    fn now() -> MonotonicTime {
        MonotonicTime::from_elapsed(std::time::Duration::ZERO)
    }

    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + std::time::Duration::from_secs(1)
    }

    fn authenticating_session(now: MonotonicTime) -> (EnterpriseResolveSession, OAuthState) {
        let mut session = EnterpriseResolveSession::new(RequestId::new(7), locator(), now);
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        (session, state)
    }

    fn entry(
        session: EnterpriseResolveSession,
        now: MonotonicTime,
    ) -> (
        CallbackEntry,
        oneshot::Receiver<CallbackCompletion>,
        oneshot::Sender<()>,
    ) {
        let (outcome_tx, outcome_rx) = oneshot::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let entry = CallbackEntry::new(
            session,
            outcome_tx,
            cancel_rx,
            RequestId::new(7),
            now.checked_add(crate::session::SESSION_LIFETIME).unwrap(),
        );
        (entry, outcome_rx, cancel_tx)
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

    fn handler_with<T: crate::verifier::ExchangeTransport>(
        exchange: T,
        entries: Vec<(OAuthState, CallbackEntry)>,
    ) -> (
        CallbackSessionHandler<FixedClock, T>,
        tokio::task::JoinHandle<CallbackRegistry>,
    ) {
        let (requests, mut incoming) = mpsc::channel(16);
        let owner = tokio::spawn(async move {
            let mut registry = CallbackRegistry::new();
            for (state, entry) in entries {
                registry.insert(state, entry, now()).unwrap();
            }
            while let Some(request) = incoming.recv().await {
                handle_callback_registry_request(&mut registry, request);
            }
            registry
        });
        (
            CallbackSessionHandler::new(
                requests,
                Arc::new(wecom_credentials()),
                exchange,
                FixedClock(now()),
            ),
            owner,
        )
    }

    async fn run_handler_case<T>(
        exchange: T,
        provider: EnterpriseProvider,
        authorization: CallbackAuthorization<'_>,
        callback_deadline: tokio::time::Instant,
    ) -> (CallbackResult, EnterpriseResolvePhase)
    where
        T: crate::verifier::ExchangeTransport + Send + Sync,
    {
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome, _cancel) = entry(session, started);
        let (handler, owner) = handler_with(exchange, vec![(state.clone(), callback_entry)]);
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        let result = handler
            .handle(
                provider,
                authorization,
                &encoded,
                "203.0.113.9".parse().unwrap(),
                callback_deadline,
            )
            .await;
        let phase = outcome.await.unwrap().into_session().phase();
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
        (result, phase)
    }

    #[test]
    fn registry_enforces_single_use_capacity_and_expiry() {
        let mut registry = CallbackRegistry::new();
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, _outcome, _cancel) = entry(session, started);
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
        let (first, _, _) = entry(session, started);
        registry.insert(state.clone(), first, started).unwrap();
        let (other_session, _) = authenticating_session(started);
        let (outcome, _received) = oneshot::channel();
        let (_cancel, cancelled) = oneshot::channel();
        let second = CallbackEntry::new(
            other_session,
            outcome,
            cancelled,
            RequestId::new(8),
            started
                .checked_add(crate::session::SESSION_LIFETIME)
                .unwrap(),
        );
        assert!(matches!(
            registry.insert(state.clone(), second, started),
            Err(CallbackRegistryError::DuplicateState)
        ));
        assert_eq!(
            registry.take(&state, started).unwrap().request_id(),
            RequestId::new(7)
        );

        // Capacity exhaustion fails closed.
        let mut small = CallbackRegistry::with_capacity(1);
        let (session, state) = authenticating_session(started);
        let (callback_entry, _, _) = entry(session, started);
        small
            .insert(state.clone(), callback_entry, started)
            .unwrap();
        let (session, other_state) = authenticating_session(started);
        let (callback_entry, _, _) = entry(session, started);
        assert!(matches!(
            small.insert(other_state, callback_entry, started),
            Err(CallbackRegistryError::Capacity)
        ));

        // Expired transactions are swept on the next insert or take.
        let expired = now().checked_add(crate::session::SESSION_LIFETIME).unwrap();
        let (session, state) = authenticating_session(now());
        let (callback_entry, _, _) = entry(session, now());
        registry
            .insert(state.clone(), callback_entry, now())
            .unwrap();
        assert!(registry.take(&state, expired).is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn state_decoding_is_strict_base64url_without_padding_of_32_bytes() {
        let (_, state) = authenticating_session(now());
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        assert_eq!(encoded.len(), 43);
        assert_eq!(decode_state(&encoded), Some(state));
        assert_eq!(decode_state(&format!("{encoded}=")), None);
        assert_eq!(decode_state(&encoded[..42]), None);
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
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome_rx, _cancel) = entry(session, started);
        let (handler, owner) = handler_with(exchange, vec![(state.clone(), callback_entry)]);
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        let result = handler
            .handle(
                EnterpriseProvider::WeCom,
                CallbackAuthorization::Code("auth-code-1"),
                &encoded,
                "203.0.113.9".parse().unwrap(),
                deadline(),
            )
            .await;
        assert_eq!(result, CallbackResult::Admitted);
        let completion = outcome_rx.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::Admitted);
        assert_eq!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Authenticated
        );
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_rejects_external_users_and_completes_the_transaction() {
        let exchange = FakeExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","external_userid":"wo_12345"}"#),
        ]);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome_rx, _cancel) = entry(session, started);
        let (handler, owner) = handler_with(exchange, vec![(state.clone(), callback_entry)]);
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        let result = handler
            .handle(
                EnterpriseProvider::WeCom,
                CallbackAuthorization::Code("auth-code-1"),
                &encoded,
                "203.0.113.9".parse().unwrap(),
                deadline(),
            )
            .await;
        assert_eq!(result, CallbackResult::Rejected);
        let completion = outcome_rx.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::Rejected);
        assert!(matches!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Failed(_)
        ));
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provider_denial_consumes_state_and_completes_without_exchange() {
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome_rx, _cancel) = entry(session, started);
        let (handler, owner) = handler_with(
            FakeExchange::new(Vec::new()),
            vec![(state.clone(), callback_entry)],
        );
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        let result = handler
            .handle(
                EnterpriseProvider::WeCom,
                CallbackAuthorization::Denied,
                &encoded,
                "203.0.113.9".parse().unwrap(),
                deadline(),
            )
            .await;
        assert_eq!(result, CallbackResult::Rejected);
        let completion = outcome_rx.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::Rejected);
        assert_eq!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Failed(EnterpriseFailure::UserRejected)
        );
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Denied,
                    &encoded,
                    "203.0.113.9".parse().unwrap(),
                    deadline(),
                )
                .await,
            CallbackResult::InvalidState
        );
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_fails_closed_on_platform_errors() {
        let exchange = FakeExchange::new(vec![Err(io::Error::other("network unreachable"))]);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome_rx, _cancel) = entry(session, started);
        let (handler, owner) = handler_with(exchange, vec![(state.clone(), callback_entry)]);
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        let result = handler
            .handle(
                EnterpriseProvider::WeCom,
                CallbackAuthorization::Code("auth-code-1"),
                &encoded,
                "203.0.113.9".parse().unwrap(),
                deadline(),
            )
            .await;
        assert_eq!(result, CallbackResult::Platform);
        let completion = outcome_rx.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::Platform);
        assert!(matches!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Failed(_)
        ));
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_rejects_unknown_and_replayed_states() {
        let exchange = FakeExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san","status":1}"#),
        ]);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, _outcome, _cancel) = entry(session, started);
        let (handler, owner) = handler_with(exchange, vec![(state.clone(), callback_entry)]);
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        // An unknown state finds no transaction.
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Code("auth-code-1"),
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "203.0.113.9".parse().unwrap(),
                    deadline(),
                )
                .await,
            CallbackResult::InvalidState
        );
        // The real state is consumed exactly once.
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Code("auth-code-1"),
                    &encoded,
                    "203.0.113.9".parse().unwrap(),
                    deadline(),
                )
                .await,
            CallbackResult::Admitted
        );
        // The replay of the consumed state finds nothing.
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Code("auth-code-1"),
                    &encoded,
                    "203.0.113.9".parse().unwrap(),
                    deadline(),
                )
                .await,
            CallbackResult::InvalidState
        );
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    struct ConcurrentWeComExchange;

    impl crate::verifier::ExchangeTransport for ConcurrentWeComExchange {
        fn get(
            &self,
            url: &Url,
            _bearer: Option<&str>,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            let path = url.path().to_owned();
            async move {
                match path.as_str() {
                    "/cgi-bin/gettoken" => ok(
                        r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#,
                    ),
                    "/cgi-bin/auth/getuserinfo" => {
                        ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#)
                    }
                    "/cgi-bin/user/get" => {
                        ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san","status":1}"#)
                    }
                    _ => Err(io::Error::other("unexpected provider request")),
                }
            }
        }

        fn post_json(
            &self,
            _url: &Url,
            _body: &str,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            std::future::ready(Err(io::Error::other("unexpected provider request")))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn six_legitimate_callbacks_from_one_corporate_nat_run_concurrently() {
        let started = now();
        let mut entries = Vec::new();
        let mut states = Vec::new();
        let mut outcomes = Vec::new();
        let mut cancel_guards = Vec::new();
        for _ in 0..6 {
            let (session, state) = authenticating_session(started);
            let (callback_entry, outcome, cancel) = entry(session, started);
            entries.push((state.clone(), callback_entry));
            states.push(data_encoding::BASE64URL_NOPAD.encode(state.as_bytes()));
            outcomes.push(outcome);
            cancel_guards.push(cancel);
        }
        let (handler, owner) = handler_with(ConcurrentWeComExchange, entries);
        let handler = Arc::new(handler);
        let source: IpAddr = "203.0.113.9".parse().unwrap();
        let mut tasks = Vec::new();
        for state in states {
            let handler = Arc::clone(&handler);
            tasks.push(tokio::spawn(async move {
                handler
                    .handle(
                        EnterpriseProvider::WeCom,
                        CallbackAuthorization::Code("auth-code-1"),
                        &state,
                        source,
                        deadline(),
                    )
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), CallbackResult::Admitted);
        }
        for outcome in outcomes {
            assert_eq!(outcome.await.unwrap().result(), CallbackResult::Admitted);
        }
        drop(cancel_guards);
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    #[test]
    fn registry_default_uses_the_documented_capacity() {
        let mut registry = CallbackRegistry::default();
        assert_eq!(registry.len(), 0);
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, _outcome, _cancel) = entry(session, started);
        registry.insert(state, callback_entry, started).unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_full_callback_owner_channel_fails_closed_without_hanging() {
        let (requests, _incoming) = mpsc::channel(1);
        let (response, _received) = oneshot::channel();
        requests
            .send(CallbackRegistryRequest::Take {
                state: OAuthState::from_bytes(&[9; OAuthState::LEN]).unwrap(),
                now: now(),
                response,
            })
            .await
            .unwrap();
        let handler = CallbackSessionHandler::new(
            requests.clone(),
            Arc::new(wecom_credentials()),
            FakeExchange::new(Vec::new()),
            FixedClock(now()),
        );
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Code("auth-code-1"),
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "203.0.113.9".parse().unwrap(),
                    tokio::time::Instant::now() + std::time::Duration::from_millis(10),
                )
                .await,
            CallbackResult::Platform
        );
        let started = now();
        let (session, _) = authenticating_session(started);
        let (callback_entry, outcome, _cancel) = entry(session, started);
        assert_eq!(
            finish_entry(
                &requests,
                callback_entry,
                CallbackResult::Admitted,
                tokio::time::Instant::now() + std::time::Duration::from_millis(10),
            )
            .await,
            CallbackResult::Platform
        );
        let completion = outcome.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::Platform);
        assert!(matches!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Failed(_)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_rejects_malformed_states_before_looking_up_transactions() {
        let exchange = FakeExchange::new(Vec::new());
        let (handler, owner) = handler_with(exchange, Vec::new());
        let source: IpAddr = "203.0.113.9".parse().unwrap();
        // A state that is not lowercase hex fails closed as malformed
        // without touching the registry.
        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Code("auth-code-1"),
                    "not-hex-state!",
                    source,
                    deadline(),
                )
                .await,
            CallbackResult::InvalidState
        );
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    struct PendingExchange;

    impl crate::verifier::ExchangeTransport for PendingExchange {
        fn get(
            &self,
            _url: &Url,
            _bearer: Option<&str>,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            std::future::pending()
        }

        fn post_json(
            &self,
            _url: &Url,
            _body: &str,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            std::future::pending()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_disconnect_cancels_an_in_flight_callback() {
        let started = now();
        let (session, state) = authenticating_session(started);
        let (callback_entry, outcome, cancel) = entry(session, started);
        let (handler, owner) = handler_with(PendingExchange, vec![(state.clone(), callback_entry)]);
        let handler = Arc::new(handler);
        let source: IpAddr = "203.0.113.9".parse().unwrap();
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        let callback = {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                handler
                    .handle(
                        EnterpriseProvider::WeCom,
                        CallbackAuthorization::Code("auth-code-1"),
                        &encoded,
                        source,
                        deadline(),
                    )
                    .await
            })
        };
        tokio::task::yield_now().await;
        cancel.send(()).unwrap();
        assert_eq!(callback.await.unwrap(), CallbackResult::InvalidState);
        let completion = outcome.await.unwrap();
        assert!(matches!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Cancelled
        ));
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owner_rechecks_disconnect_before_committing_a_queued_completion() {
        let started = now();
        let (session, _state) = authenticating_session(started);
        let (callback_entry, outcome, cancel) = entry(session, started);
        cancel.send(()).unwrap();
        let (response, received) = oneshot::channel();
        let mut registry = CallbackRegistry::new();
        handle_callback_registry_request(
            &mut registry,
            CallbackRegistryRequest::Complete {
                entry: callback_entry,
                result: CallbackResult::Admitted,
                deadline: deadline(),
                response,
            },
        );
        assert_eq!(received.await.unwrap(), CallbackResult::InvalidState);
        let completion = outcome.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::InvalidState);
        assert_eq!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Cancelled
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owner_fails_an_expired_completion_before_committing_it() {
        let started = now();
        let (session, _state) = authenticating_session(started);
        let (callback_entry, outcome, _cancel) = entry(session, started);
        let (response, received) = oneshot::channel();
        let mut registry = CallbackRegistry::new();
        handle_callback_registry_request(
            &mut registry,
            CallbackRegistryRequest::Complete {
                entry: callback_entry,
                result: CallbackResult::Admitted,
                deadline: tokio::time::Instant::now()
                    .checked_sub(std::time::Duration::from_millis(1))
                    .unwrap(),
                response,
            },
        );
        assert_eq!(received.await.unwrap(), CallbackResult::Platform);
        let completion = outcome.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::Platform);
        assert_eq!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Failed(EnterpriseFailure::Platform)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_fails_closed_for_mismatch_invalid_code_and_provider_failure() {
        assert_eq!(
            run_handler_case(
                FakeExchange::new(Vec::new()),
                EnterpriseProvider::Feishu,
                CallbackAuthorization::Code("auth-code-1"),
                deadline(),
            )
            .await,
            (
                CallbackResult::InvalidState,
                EnterpriseResolvePhase::Failed(EnterpriseFailure::InvalidState)
            )
        );
        assert_eq!(
            run_handler_case(
                FakeExchange::new(Vec::new()),
                EnterpriseProvider::WeCom,
                CallbackAuthorization::Code(""),
                deadline(),
            )
            .await,
            (
                CallbackResult::InvalidState,
                EnterpriseResolvePhase::Failed(EnterpriseFailure::InvalidState)
            )
        );
        assert_eq!(
            run_handler_case(
                FakeExchange::new(Vec::new()),
                EnterpriseProvider::WeCom,
                CallbackAuthorization::ProviderFailed,
                deadline(),
            )
            .await,
            (
                CallbackResult::Platform,
                EnterpriseResolvePhase::Failed(EnterpriseFailure::Platform)
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_bounds_pending_verification_by_the_callback_deadline() {
        assert_eq!(
            run_handler_case(
                PendingExchange,
                EnterpriseProvider::WeCom,
                CallbackAuthorization::Code("auth-code-1"),
                tokio::time::Instant::now() + std::time::Duration::from_millis(20),
            )
            .await,
            (
                CallbackResult::Platform,
                EnterpriseResolvePhase::Failed(EnterpriseFailure::Platform)
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completion_response_loss_fails_closed() {
        let (requests, mut incoming) = mpsc::channel(1);
        let owner = tokio::spawn(async move {
            let Some(CallbackRegistryRequest::Complete { response, .. }) = incoming.recv().await
            else {
                panic!("completion request expected");
            };
            drop(response);
        });
        let started = now();
        let (session, _state) = authenticating_session(started);
        let (callback_entry, outcome, _cancel) = entry(session, started);
        assert_eq!(
            finish_entry(
                &requests,
                callback_entry,
                CallbackResult::Admitted,
                deadline(),
            )
            .await,
            CallbackResult::Platform
        );
        assert!(outcome.await.is_err());
        owner.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn callback_fails_closed_when_the_registry_owner_drops_the_take_response() {
        let (requests, mut incoming) = mpsc::channel(1);
        let owner = tokio::spawn(async move {
            let Some(CallbackRegistryRequest::Take { response, .. }) = incoming.recv().await else {
                panic!("take request expected");
            };
            drop(response);
        });
        let state = OAuthState::from_bytes(&[0xA5; 32]).unwrap();
        let encoded = data_encoding::BASE64URL_NOPAD.encode(state.as_bytes());
        let handler = CallbackSessionHandler::new(
            requests,
            Arc::new(wecom_credentials()),
            FakeExchange::new(Vec::new()),
            FixedClock(now()),
        );

        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Code("auth-code-1"),
                    &encoded,
                    "203.0.113.9".parse().unwrap(),
                    deadline(),
                )
                .await,
            CallbackResult::Platform
        );
        owner.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verified_identity_cannot_complete_a_different_registered_oauth_state() {
        let exchange = FakeExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san","status":1}"#),
        ]);
        let started = now();
        let (session, session_state) = authenticating_session(started);
        let registered_state = OAuthState::from_bytes(&[0x5A; 32]).unwrap();
        assert_ne!(registered_state, session_state);
        let (callback_entry, outcome, _cancel) = entry(session, started);
        let (handler, owner) =
            handler_with(exchange, vec![(registered_state.clone(), callback_entry)]);
        let encoded = data_encoding::BASE64URL_NOPAD.encode(registered_state.as_bytes());

        assert_eq!(
            handler
                .handle(
                    EnterpriseProvider::WeCom,
                    CallbackAuthorization::Code("auth-code-1"),
                    &encoded,
                    "203.0.113.9".parse().unwrap(),
                    deadline(),
                )
                .await,
            CallbackResult::InvalidState
        );
        let completion = outcome.await.unwrap();
        assert_eq!(completion.result(), CallbackResult::InvalidState);
        assert_eq!(
            completion.into_session().phase(),
            EnterpriseResolvePhase::Failed(EnterpriseFailure::InvalidState)
        );
        drop(handler);
        assert!(owner.await.unwrap().is_empty());
    }
}
