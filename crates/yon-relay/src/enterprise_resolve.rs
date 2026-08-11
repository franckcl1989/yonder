//! Enterprise resolve substream exchange and admission control (design
//! section 4): the session flow owned by the substream task, the
//! owner-serialized admission and post-authentication resolution
//! requests, and the fail-closed transaction guard.

use crate::callback::CallbackResult;
use crate::callback_session::{CallbackEntry, CallbackRegistry};
use crate::enterprise::CallbackExternalUrl;
use crate::provider::ProviderCredentials;
use crate::service::{ProtocolIo, ProtocolTaskError, read_deadline, read_timeout, write_timeout};
use crate::session::{
    EnterpriseFailure, EnterpriseResolvePhase, EnterpriseResolveSession, OAuthState, RequestId,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{mpsc, oneshot};
use yonder_core::rate::{DirectRateLimiter, RateLimit};
use yonder_core::wire::enterprise::{
    EnterpriseResolveResponse, EnterpriseSelect, EnterpriseStart, SELECT_LEN, START_LEN,
};
use yonder_core::{
    EnterpriseProvider, Locator, MonotonicClock, MonotonicTime, OsSecureRandom, RetryAfter,
    SecureRandom,
};
use yonder_net::{ConnectionBook, PeerId, SourcePrefix};

/// Bound on the per-source enterprise start limiter table.
const ENTERPRISE_SOURCE_CAPACITY: usize = 1024;
/// How long an enterprise source limiter stays in the table.
const ENTERPRISE_SOURCE_IDLE: Duration = Duration::from_secs(10 * 60);

/// Checks enterprise start admission: the global limiter, then the
/// unique-connection source limiter (design section 11).
pub(crate) fn handle_enterprise_admission<C: yonder_core::MonotonicClock>(
    peer: PeerId,
    connections: &ConnectionBook,
    clock: &C,
    limiters: &mut EnterpriseLimiters,
    retry_after: RetryAfter,
) -> Result<EnterpriseResolveAdmission, ProtocolTaskError> {
    if !limiters.global.check() {
        return Ok(EnterpriseResolveAdmission::Retry(retry_after));
    }
    let Some(source) = connections
        .unique(&peer)
        .and_then(|connection| connection.source_prefix())
    else {
        return Ok(EnterpriseResolveAdmission::Retry(retry_after));
    };
    if !limiters.check_source(source, clock.now()) {
        return Ok(EnterpriseResolveAdmission::Retry(retry_after));
    }
    Ok(EnterpriseResolveAdmission::Admitted)
}

/// Enterprise resolve start admission: the shared authentication limiter
/// over a bounded per-source table.
pub(crate) struct EnterpriseLimiters {
    global: DirectRateLimiter,
    sources: HashMap<SourcePrefix, (DirectRateLimiter, MonotonicTime)>,
}

impl EnterpriseLimiters {
    pub(crate) fn new() -> Self {
        Self {
            global: DirectRateLimiter::new(RateLimit::authentication()),
            sources: HashMap::with_capacity(64),
        }
    }

    /// Checks the bounded source table only; the caller checked global.
    fn check_source(&mut self, source: SourcePrefix, now: MonotonicTime) -> bool {
        self.prune(now);
        if let Some((limiter, last_seen)) = self.sources.get_mut(&source) {
            *last_seen = now;
            return limiter.check();
        }
        if self.sources.len() >= ENTERPRISE_SOURCE_CAPACITY {
            return false;
        }
        let limiter = DirectRateLimiter::new(RateLimit::authentication());
        let allowed = limiter.check();
        self.sources.insert(source, (limiter, now));
        allowed
    }

    fn prune(&mut self, now: MonotonicTime) {
        self.sources.retain(|_, (_, last_seen)| {
            now.duration_since(*last_seen)
                .is_none_or(|age| age < ENTERPRISE_SOURCE_IDLE)
        });
    }
}

/// The start admission decision for one enterprise resolve substream.
#[derive(Debug)]
pub(crate) enum EnterpriseResolveAdmission {
    Admitted,
    Retry(RetryAfter),
}

/// Owner-side requests of the enterprise resolve flow.
pub(crate) enum EnterpriseResolveRequest {
    /// Admission for a start request: global and per-source limits.
    AdmitStart {
        peer: PeerId,
        response: oneshot::Sender<Result<EnterpriseResolveAdmission, ProtocolTaskError>>,
    },
    /// The post-authentication locator resolution.
    ResolveTarget {
        locator: Locator,
        response: oneshot::Sender<Result<EnterpriseResolveResponse, ProtocolTaskError>>,
    },
}

/// Removes the transaction from the registry unless the callback already
/// consumed it, so a dropped substream frees its slot immediately
/// (design section 8: disconnect invalidates the transaction).
struct TransactionGuard {
    registry: Arc<CallbackRegistry>,
    state: OAuthState,
    armed: bool,
}

impl TransactionGuard {
    fn new(registry: Arc<CallbackRegistry>, state: OAuthState) -> Self {
        Self {
            registry,
            state,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        if self.armed {
            self.registry.remove(&self.state);
        }
    }
}

/// Everything the enterprise resolve exchange needs beyond the substream.
pub(crate) struct EnterpriseExchangeContext {
    pub(crate) registry: Arc<CallbackRegistry>,
    pub(crate) credentials: Arc<ProviderCredentials>,
    pub(crate) callback_url: CallbackExternalUrl,
}

/// Redacted failure context shared between the exchange body and its
/// logging wrapper (design section 10 whitelist: request id, platform,
/// phase and redacted result only). The body records the session
/// checkpoints; the wrapper logs them when the body fails after session
/// creation, while pre-session failures keep no log inside the exchange.
#[derive(Default)]
struct EnterpriseFailureContext {
    request_id: Option<RequestId>,
    provider: Option<EnterpriseProvider>,
    phase: Option<EnterpriseResolvePhase>,
}

/// Waits for the connect peer to close the substream while the browser
/// callback is pending: reading zero bytes is EOF, so the transaction is
/// invalidated immediately (design section 8: 断开立即失效). Stray bytes
/// are a protocol violation at this point of the flow but do not count as
/// a disconnect, so they are consumed and the wait continues.
async fn wait_for_peer_close(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<(), ProtocolTaskError> {
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// One enterprise resolve transaction, owned by the substream task.
///
/// Flow (design section 4): start request, provider offer, provider
/// selection, single-use OAuth state and authorization URL, transaction
/// registration, browser callback outcome, internal resolve, response.
/// The owner task serializes admission and the final resolve; the
/// transaction registry is shared with the callback server. Failures
/// after session creation are logged here with the request id (design
/// section 10); pre-session failures keep a debug log at the spawn site.
pub(crate) async fn enterprise_resolve_exchange<S: ProtocolIo, C: MonotonicClock>(
    peer: PeerId,
    stream: S,
    calls: mpsc::Sender<EnterpriseResolveRequest>,
    context: EnterpriseExchangeContext,
    clock: C,
    random: OsSecureRandom,
) -> Result<(), ProtocolTaskError> {
    let mut failure = EnterpriseFailureContext::default();
    let result = enterprise_resolve_exchange_inner(
        peer,
        stream,
        calls,
        context,
        clock,
        random,
        &mut failure,
    )
    .await;
    if let Err(error) = &result
        && let Some(request_id) = failure.request_id
    {
        let platform = failure
            .provider
            .map(EnterpriseProvider::as_str)
            .unwrap_or("unknown");
        let phase = failure
            .phase
            .map(|phase| format!("{phase:?}"))
            .unwrap_or_else(|| "unknown".to_owned());
        tracing::warn!(
            event = "enterprise_resolve_failed",
            request_id = %request_id,
            platform,
            phase,
            result = %error,
            "enterprise resolve exchange failed"
        );
    }
    result
}

async fn enterprise_resolve_exchange_inner<S: ProtocolIo, C: MonotonicClock>(
    peer: PeerId,
    stream: S,
    calls: mpsc::Sender<EnterpriseResolveRequest>,
    context: EnterpriseExchangeContext,
    clock: C,
    mut random: OsSecureRandom,
    failure: &mut EnterpriseFailureContext,
) -> Result<(), ProtocolTaskError> {
    let EnterpriseExchangeContext {
        registry,
        credentials,
        callback_url,
    } = &context;
    let mut stream = stream.into_protocol_io();
    let start = EnterpriseStart::decode(&read_timeout::<START_LEN>(&mut stream).await?)?;
    let (response_tx, response_rx) = oneshot::channel();
    calls
        .send(EnterpriseResolveRequest::AdmitStart {
            peer,
            response: response_tx,
        })
        .await
        .map_err(|_| ProtocolTaskError::OwnerStopped)?;
    let admission = response_rx
        .await
        .map_err(|_| ProtocolTaskError::OwnerStopped)??;
    if let EnterpriseResolveAdmission::Retry(retry) = admission {
        return write_timeout(
            &mut stream,
            EnterpriseResolveResponse::Retry(retry).encode().as_slice(),
        )
        .await;
    }

    let now = clock.now();
    let mut id_bytes = [0_u8; 8];
    random.try_fill(&mut id_bytes)?;
    let request_id = RequestId::new(u64::from_be_bytes(id_bytes));
    failure.request_id = Some(request_id);
    failure.phase = Some(EnterpriseResolvePhase::Created);
    let mut session = EnterpriseResolveSession::new(request_id, start.locator(), now);
    session.offer_providers()?;
    failure.phase = Some(EnterpriseResolvePhase::ProviderSelection);
    let providers = credentials.providers()?;
    write_timeout(
        &mut stream,
        EnterpriseResolveResponse::Providers(providers)
            .encode()
            .as_slice(),
    )
    .await?;

    // The provider selection is a human interaction, so it is bounded by
    // the session deadline rather than the message timeout.
    let select_deadline = session
        .deadline()
        .duration_since(clock.now())
        .unwrap_or(Duration::ZERO);
    let select = EnterpriseSelect::decode(
        &read_deadline::<SELECT_LEN>(&mut stream, select_deadline).await?,
    )?;
    let provider = select.provider();
    if !providers.contains(provider) {
        let _ = session.fail(EnterpriseFailure::InvalidState);
        failure.phase = Some(EnterpriseResolvePhase::Failed(
            EnterpriseFailure::InvalidState,
        ));
        return write_timeout(
            &mut stream,
            EnterpriseResolveResponse::Failed.encode().as_slice(),
        )
        .await;
    }
    let state = session.select(provider, &mut random)?;
    failure.provider = Some(provider);
    failure.phase = Some(EnterpriseResolvePhase::Authenticating);
    let url = credentials.authorization_url(provider, callback_url, &state)?;

    let (outcome_tx, outcome_rx) = oneshot::channel();
    let deadline = session.deadline();
    let session = Arc::new(Mutex::new(session));
    let entry = CallbackEntry::new(Arc::clone(&session), outcome_tx, request_id, deadline);
    if registry.insert(state.clone(), entry, clock.now()).is_err() {
        let _ = session.lock().unwrap().fail(EnterpriseFailure::Platform);
        failure.phase = Some(EnterpriseResolvePhase::Failed(EnterpriseFailure::Platform));
        return write_timeout(
            &mut stream,
            EnterpriseResolveResponse::Failed.encode().as_slice(),
        )
        .await;
    }
    let mut transaction = TransactionGuard::new(Arc::clone(registry), state.clone());

    write_timeout(
        &mut stream,
        EnterpriseResolveResponse::Authenticate(Box::new(url))
            .encode()
            .as_slice(),
    )
    .await?;

    let remaining = deadline
        .duration_since(clock.now())
        .unwrap_or(Duration::ZERO);
    let outcome = tokio::select! {
        received = outcome_rx => received.unwrap_or(CallbackResult::Platform),
        () = tokio::time::sleep(remaining) => {
            let _ = session.lock().unwrap().expire();
            failure.phase = Some(EnterpriseResolvePhase::Expired);
            return write_timeout(&mut stream, EnterpriseResolveResponse::Expired.encode().as_slice()).await;
        }
        closed = wait_for_peer_close(&mut stream) => {
            // The connect peer closed the substream while the browser
            // callback was pending: the transaction dies immediately
            // (design section 8: 断开立即失效). Cancelling the session and
            // dropping the still-armed guard release the registry slot at
            // once. EOF is a client-initiated disconnect, so the exchange
            // ends like the other exchanges do on stream close.
            let _ = session.lock().unwrap().cancel();
            failure.phase = Some(EnterpriseResolvePhase::Cancelled);
            closed?;
            return Ok(());
        }
    };
    transaction.disarm();

    match outcome {
        CallbackResult::Admitted => {
            // The session transitions run inside scopes so the guard
            // never lives across an await.
            let expired = {
                let mut guard = session.lock().unwrap();
                if guard.is_expired(clock.now()) {
                    let _ = guard.expire();
                    true
                } else {
                    guard.begin_resolve()?;
                    false
                }
            };
            if expired {
                failure.phase = Some(EnterpriseResolvePhase::Expired);
                return write_timeout(
                    &mut stream,
                    EnterpriseResolveResponse::Expired.encode().as_slice(),
                )
                .await;
            }
            failure.phase = Some(EnterpriseResolvePhase::Resolving);
            let locator = session.lock().unwrap().locator();
            let (response_tx, response_rx) = oneshot::channel();
            calls
                .send(EnterpriseResolveRequest::ResolveTarget {
                    locator,
                    response: response_tx,
                })
                .await
                .map_err(|_| ProtocolTaskError::OwnerStopped)?;
            let target = response_rx
                .await
                .map_err(|_| ProtocolTaskError::OwnerStopped)??;
            {
                let mut guard = session.lock().unwrap();
                match &target {
                    EnterpriseResolveResponse::Resolved(peer) => {
                        guard.complete(peer.clone())?;
                        failure.phase = Some(EnterpriseResolvePhase::Completed);
                    }
                    _ => {
                        guard.unavailable()?;
                        failure.phase = Some(EnterpriseResolvePhase::Unavailable);
                    }
                }
            }
            write_timeout(&mut stream, target.encode().as_slice()).await
        }
        CallbackResult::Rejected
        | CallbackResult::InvalidState
        | CallbackResult::Platform
        | CallbackResult::Limited => {
            failure.phase = Some(EnterpriseResolvePhase::Failed(match outcome {
                CallbackResult::Rejected => EnterpriseFailure::UserRejected,
                CallbackResult::InvalidState => EnterpriseFailure::InvalidState,
                CallbackResult::Platform | CallbackResult::Limited => EnterpriseFailure::Platform,
                CallbackResult::Admitted => unreachable!(),
            }));
            write_timeout(
                &mut stream,
                EnterpriseResolveResponse::Failed.encode().as_slice(),
            )
            .await
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        ENTERPRISE_SOURCE_CAPACITY, ENTERPRISE_SOURCE_IDLE, EnterpriseExchangeContext,
        EnterpriseLimiters, EnterpriseResolveAdmission, EnterpriseResolveRequest, TransactionGuard,
        enterprise_resolve_exchange, handle_enterprise_admission,
    };
    use crate::callback::CallbackResult;
    use crate::callback_session::{CallbackEntry, CallbackRegistry};
    use crate::enterprise::CallbackExternalUrl;
    use crate::provider::{ProviderCredentials, ProviderField, SecretText, WeComCredentials};
    use crate::service::ProtocolTaskError;
    use crate::session::{
        EnterpriseFailure, EnterpriseResolvePhase, EnterpriseResolveSession, MemberAdmission,
        MemberIdentity, OAuthState, RequestId,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::{mpsc, oneshot};
    use url::Url;
    use yonder_core::wire::enterprise::{
        EnterpriseResolveResponse, EnterpriseSelect, EnterpriseStart,
    };
    use yonder_core::{
        EnterpriseProvider, EnterpriseProviders, Locator, MonotonicClock, MonotonicTime,
        OsSecureRandom, RetryAfter, SystemClock,
    };
    use yonder_net::{ConnectedPoint, ConnectionBook, ConnectionId, Keypair, SourcePrefix};

    // ---- enterprise resolve exchange ----

    fn locator() -> Locator {
        Locator::new(0x12345).unwrap()
    }

    fn wecom_credentials() -> Arc<ProviderCredentials> {
        let wecom = WeComCredentials {
            corp_id: SecretText::new("ww1234567890abcdef".into(), ProviderField::CorpId).unwrap(),
            agent_id: 7,
            app_secret: SecretText::new("s3cret".into(), ProviderField::AppSecret).unwrap(),
        };
        Arc::new(ProviderCredentials::from_credentials(Some(wecom), None))
    }

    fn enterprise_context(registry: Arc<CallbackRegistry>) -> EnterpriseExchangeContext {
        EnterpriseExchangeContext {
            registry,
            credentials: wecom_credentials(),
            callback_url: CallbackExternalUrl::new(
                Url::parse("https://relay.example.test").unwrap(),
            )
            .unwrap(),
        }
    }

    /// Reads one encoded enterprise response from the client side.
    async fn read_enterprise_response(
        stream: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> EnterpriseResolveResponse {
        let mut tag = [0_u8; 1];
        stream.read_exact(&mut tag).await.unwrap();
        let message = match tag[0] {
            0x10 => {
                let mut payload = [0_u8; 1];
                stream.read_exact(&mut payload).await.unwrap();
                vec![0x10, payload[0]]
            }
            0x11 => {
                let mut payload = [0_u8; 4];
                stream.read_exact(&mut payload).await.unwrap();
                std::iter::once(0x11).chain(payload).collect()
            }
            0x12 => {
                let mut length = [0_u8; 2];
                stream.read_exact(&mut length).await.unwrap();
                let mut url = vec![0_u8; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut url).await.unwrap();
                std::iter::once(0x12).chain(length).chain(url).collect()
            }
            0x13 => {
                let mut peer_length = [0_u8; 1];
                stream.read_exact(&mut peer_length).await.unwrap();
                let mut peer = vec![0_u8; usize::from(peer_length[0])];
                stream.read_exact(&mut peer).await.unwrap();
                std::iter::once(0x13)
                    .chain(peer_length)
                    .chain(peer)
                    .collect()
            }
            tag => vec![tag],
        };
        EnterpriseResolveResponse::decode(&message).unwrap()
    }

    /// Simulates the browser callback exactly like the callback handler:
    /// the registry take consumes the state, the session transitions run,
    /// and the outcome is sent to the exchange.
    async fn simulate_callback(registry: &CallbackRegistry, state_hex: &str) {
        let state = OAuthState::from_bytes(
            &data_encoding::HEXLOWER
                .decode(state_hex.as_bytes())
                .unwrap(),
        )
        .unwrap();
        let entry = registry.take(&state, SystemClock::new().now()).unwrap();
        let session = entry.session();
        {
            let mut guard = session.lock().unwrap();
            guard
                .callback(&state, MemberIdentity::new(b"member-123").unwrap())
                .unwrap();
            assert_eq!(
                guard.validate_member(true).unwrap(),
                MemberAdmission::Admitted
            );
        }
        entry.into_outcome().send(CallbackResult::Admitted).unwrap();
    }

    /// Drives the client side through start and providers, and returns
    /// the offered provider set.
    async fn client_offer_providers(
        client: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    ) -> EnterpriseProviders {
        client
            .write_all(&EnterpriseStart::new(locator()).encode())
            .await
            .unwrap();
        let EnterpriseResolveResponse::Providers(providers) =
            read_enterprise_response(client).await
        else {
            panic!("expected providers response");
        };
        providers
    }

    /// Selects one provider and returns the authorization URL from the
    /// exchange.
    async fn client_select_provider(
        client: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        select: EnterpriseProvider,
    ) -> Url {
        client
            .write_all(&EnterpriseSelect::new(select).encode())
            .await
            .unwrap();
        let EnterpriseResolveResponse::Authenticate(url) = read_enterprise_response(client).await
        else {
            panic!("expected authenticate response");
        };
        Url::parse(url.as_str()).unwrap()
    }

    /// A clock the test can advance to push a session past its deadline.
    #[derive(Clone)]
    struct AdvancingClock(Arc<std::sync::Mutex<MonotonicTime>>);

    impl AdvancingClock {
        fn at(now: MonotonicTime) -> Self {
            Self(Arc::new(std::sync::Mutex::new(now)))
        }

        fn advance_to(&self, now: MonotonicTime) {
            *self.0.lock().unwrap() = now;
        }
    }

    impl MonotonicClock for AdvancingClock {
        fn now(&self) -> MonotonicTime {
            *self.0.lock().unwrap()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_completes_after_callback() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));
        let resolved =
            yonder_net::peer_id_bytes(Keypair::generate_ed25519().public().to_peer_id()).unwrap();

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart {
                peer: admitted,
                response,
            } = call
            else {
                panic!("expected admission call");
            };
            assert_eq!(admitted, peer);
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits for admission");
            let call = calls_rx.recv().await.expect("resolve call");
            let EnterpriseResolveRequest::ResolveTarget {
                locator: target_locator,
                response,
            } = call
            else {
                panic!("expected resolve call");
            };
            assert_eq!(target_locator, locator());
            response
                .send(Ok(EnterpriseResolveResponse::Resolved(resolved.clone())))
                .expect("exchange waits for resolve");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            simulate_callback(&registry, &state_hex).await;
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Resolved(resolved.clone())
            );
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_expires_waiting_callbacks() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));
        let started = MonotonicTime::from_elapsed(Duration::ZERO);
        let clock = AdvancingClock::at(started);

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            // Advance the clock past the session deadline before the
            // selection arrives, so the remaining wait collapses to zero.
            clock.advance_to(
                started
                    .checked_add(crate::session::SESSION_LIFETIME)
                    .unwrap()
                    .checked_add(Duration::from_secs(1))
                    .unwrap(),
            );
            client
                .write_all(&EnterpriseSelect::new(EnterpriseProvider::WeCom).encode())
                .await
                .unwrap();
            // The exchange always sends the authorization URL before
            // waiting; the collapsed deadline then answers Expired.
            assert!(matches!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Authenticate(_)
            ));
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Expired
            );
        };

        let exchange_clock = clock.clone();
        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            exchange_clock,
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_expires_after_a_late_callback() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));
        let started = MonotonicTime::from_elapsed(Duration::ZERO);
        let clock = AdvancingClock::at(started);

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            // The callback arrives, but the clock shows the session has
            // expired, so the exchange answers Expired instead of resolving.
            clock.advance_to(
                started
                    .checked_add(crate::session::SESSION_LIFETIME)
                    .unwrap()
                    .checked_add(Duration::from_secs(1))
                    .unwrap(),
            );
            simulate_callback(&registry, &state_hex).await;
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Expired
            );
        };

        let exchange_clock = clock.clone();
        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            exchange_clock,
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_retries_on_admission_limits() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(64);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        let context = enterprise_context(Arc::new(CallbackRegistry::new()));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Retry(
                    RetryAfter::from_millis(5_000).unwrap(),
                )))
                .expect("exchange waits");
        };

        let client_side = async {
            client
                .write_all(&EnterpriseStart::new(locator()).encode())
                .await
                .unwrap();
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Retry(RetryAfter::from_millis(5_000).unwrap())
            );
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_rejects_unconfigured_providers() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(64);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        let context = enterprise_context(Arc::new(CallbackRegistry::new()));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            // Selecting the unconfigured platform fails the session closed.
            client
                .write_all(&EnterpriseSelect::new(EnterpriseProvider::Feishu).encode())
                .await
                .unwrap();
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Failed
            );
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_fails_closed_when_registry_is_full() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(64);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        let context = enterprise_context(Arc::new(CallbackRegistry::with_capacity(0)));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            // The transaction registry is full, so the exchange fails closed
            // instead of registering the transaction.
            client
                .write_all(&EnterpriseSelect::new(EnterpriseProvider::WeCom).encode())
                .await
                .unwrap();
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Failed
            );
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_reports_unavailable_targets() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
            let call = calls_rx.recv().await.expect("resolve call");
            let EnterpriseResolveRequest::ResolveTarget { response, .. } = call else {
                panic!("expected resolve call");
            };
            response
                .send(Ok(EnterpriseResolveResponse::Unavailable))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            simulate_callback(&registry, &state_hex).await;
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Unavailable
            );
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_fails_closed_on_a_limited_outcome() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            // Take the transaction and report the Limited outcome (the
            // callback source exceeded the rate limit), failing the
            // session closed first exactly like the callback handler does
            // for the other failure outcomes.
            let state = OAuthState::from_bytes(
                &data_encoding::HEXLOWER
                    .decode(state_hex.as_bytes())
                    .unwrap(),
            )
            .unwrap();
            let entry = registry.take(&state, SystemClock::new().now()).unwrap();
            let session = entry.session();
            {
                let mut guard = session.lock().unwrap();
                guard.fail(EnterpriseFailure::Platform).unwrap();
            }
            entry.into_outcome().send(CallbackResult::Limited).unwrap();
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Failed
            );
            assert!(session.lock().unwrap().is_terminal());
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_cancels_the_transaction_on_disconnect() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            // The transaction is registered while the browser callback is
            // pending. Take it to hold the session across the disconnect,
            // then put it back so the exchange guard still releases the
            // slot when it observes the closed substream.
            let state = OAuthState::from_bytes(
                &data_encoding::HEXLOWER
                    .decode(state_hex.as_bytes())
                    .unwrap(),
            )
            .unwrap();
            let entry = registry.take(&state, SystemClock::new().now()).unwrap();
            let session = entry.session();
            registry
                .insert(state, entry, SystemClock::new().now())
                .unwrap();
            drop(client);
            session
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        // The disconnect must end the exchange immediately, not at the
        // session expiry (design section 8: 断开立即失效).
        let (result, session, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), exchange),
            client_side,
            owner,
        );
        result
            .expect("the exchange must return promptly on disconnect")
            .unwrap();
        assert!(registry.is_empty());
        assert!(matches!(
            session.lock().unwrap().phase(),
            EnterpriseResolvePhase::Cancelled
        ));
    }

    /// Wraps a duplex so reads fail with an I/O error once the client has
    /// signalled the failure, simulating a substream that dies with an
    /// error instead of a clean EOF.
    struct ReadErrorStream {
        inner: tokio::io::DuplexStream,
        fail: Arc<std::sync::atomic::AtomicBool>,
    }

    impl tokio::io::AsyncRead for ReadErrorStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return std::task::Poll::Ready(Err(std::io::Error::other("substream I/O failed")));
            }
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
        }
    }

    impl tokio::io::AsyncWrite for ReadErrorStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(context)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
        }
    }

    impl crate::service::ProtocolIo for ReadErrorStream {
        fn into_protocol_io(self) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
            self
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_stops_when_the_owner_channel_is_gone() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        drop(calls_rx);
        let context = enterprise_context(Arc::new(CallbackRegistry::new()));

        let client_side = async {
            client
                .write_all(&EnterpriseStart::new(locator()).encode())
                .await
                .unwrap();
            // The exchange stops without writing anything: the substream
            // closes and the client sees EOF.
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await;
            match read {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                Ok(Ok(_)) => panic!("the exchange wrote data after the owner stopped"),
                Err(_) => panic!("the exchange did not stop"),
            }
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, ()) = tokio::join!(exchange, client_side);
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_stops_when_the_owner_drops_the_admission() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        let context = enterprise_context(Arc::new(CallbackRegistry::new()));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            drop(response);
        };

        let client_side = async {
            client
                .write_all(&EnterpriseStart::new(locator()).encode())
                .await
                .unwrap();
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await;
            match read {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => panic!("the exchange did not stop after the dropped admission: {other:?}"),
            }
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_stops_when_the_owner_drops_the_resolution() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
            let call = calls_rx.recv().await.expect("resolve call");
            let EnterpriseResolveRequest::ResolveTarget { response, .. } = call else {
                panic!("expected resolve call");
            };
            drop(response);
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            simulate_callback(&registry, &state_hex).await;
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await;
            match read {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => {
                    panic!("the exchange did not stop after the dropped resolution: {other:?}")
                }
            }
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_fails_closed_on_a_rejected_outcome() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            // The member was rejected: the session dies and the exchange
            // answers Failed, exactly like the callback handler does.
            let state = OAuthState::from_bytes(
                &data_encoding::HEXLOWER
                    .decode(state_hex.as_bytes())
                    .unwrap(),
            )
            .unwrap();
            let entry = registry.take(&state, SystemClock::new().now()).unwrap();
            let session = entry.session();
            {
                let mut guard = session.lock().unwrap();
                guard.fail(EnterpriseFailure::UserRejected).unwrap();
            }
            entry.into_outcome().send(CallbackResult::Rejected).unwrap();
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Failed
            );
            assert!(session.lock().unwrap().is_terminal());
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_fails_closed_on_an_invalid_state_outcome() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            // The state was spent or mismatched: the session dies and the
            // exchange answers Failed.
            let state = OAuthState::from_bytes(
                &data_encoding::HEXLOWER
                    .decode(state_hex.as_bytes())
                    .unwrap(),
            )
            .unwrap();
            let entry = registry.take(&state, SystemClock::new().now()).unwrap();
            let session = entry.session();
            {
                let mut guard = session.lock().unwrap();
                guard.fail(EnterpriseFailure::InvalidState).unwrap();
            }
            entry
                .into_outcome()
                .send(CallbackResult::InvalidState)
                .unwrap();
            assert_eq!(
                read_enterprise_response(&mut client).await,
                EnterpriseResolveResponse::Failed
            );
            assert!(session.lock().unwrap().is_terminal());
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_fails_closed_on_invalid_selection_bytes() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        let context = enterprise_context(Arc::new(CallbackRegistry::new()));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            // A selection with an unknown tag is a protocol violation.
            client.write_all(&[0xFF, 0x00]).await.unwrap();
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await;
            match read {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => panic!("the exchange answered a malformed selection: {other:?}"),
            }
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        assert!(matches!(result, Err(ProtocolTaskError::Protocol(_))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_stops_when_the_client_drops_after_start() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        let context = enterprise_context(Arc::new(CallbackRegistry::new()));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            client
                .write_all(&EnterpriseStart::new(locator()).encode())
                .await
                .unwrap();
            // The client disappears before the providers offer is sent:
            // the exchange's write fails and the exchange ends.
            drop(client);
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        assert!(matches!(result, Err(ProtocolTaskError::Io(_))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_stops_when_the_client_drops_after_selection() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(1);
        let context = enterprise_context(Arc::new(CallbackRegistry::new()));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            client
                .write_all(&EnterpriseSelect::new(EnterpriseProvider::WeCom).encode())
                .await
                .unwrap();
            // The client disappears before the authorization URL is sent.
            drop(client);
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, (), ()) = tokio::join!(exchange, client_side, owner);
        assert!(matches!(result, Err(ProtocolTaskError::Io(_))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_consumes_stray_bytes_before_the_close() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut client, server) = tokio::io::duplex(1024);
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            // Hold the transaction, then write stray bytes and close: the
            // exchange consumes the stray bytes and treats the close as a
            // disconnect (design section 8).
            let state = OAuthState::from_bytes(
                &data_encoding::HEXLOWER
                    .decode(state_hex.as_bytes())
                    .unwrap(),
            )
            .unwrap();
            let entry = registry.take(&state, SystemClock::new().now()).unwrap();
            let session = entry.session();
            registry
                .insert(state, entry, SystemClock::new().now())
                .unwrap();
            client.write_all(b"stray bytes").await.unwrap();
            drop(client);
            session
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, session, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), exchange),
            client_side,
            owner,
        );
        result
            .expect("the exchange must return promptly on disconnect")
            .unwrap();
        assert!(registry.is_empty());
        assert!(matches!(
            session.lock().unwrap().phase(),
            EnterpriseResolvePhase::Cancelled
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_resolve_exchange_propagates_substream_read_errors() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (client, server) = tokio::io::duplex(1024);
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = ReadErrorStream {
            inner: server,
            fail: Arc::clone(&fail),
        };
        let (calls_tx, mut calls_rx) = mpsc::channel::<EnterpriseResolveRequest>(4);
        let registry = Arc::new(CallbackRegistry::new());
        let context = enterprise_context(Arc::clone(&registry));

        let owner = async {
            let call = calls_rx.recv().await.expect("admission call");
            let EnterpriseResolveRequest::AdmitStart { response, .. } = call else {
                panic!("expected admission call");
            };
            response
                .send(Ok(EnterpriseResolveAdmission::Admitted))
                .expect("exchange waits");
        };

        let client_side = async {
            let mut client = client;
            let providers = client_offer_providers(&mut client).await;
            assert_eq!(providers, EnterpriseProviders::new(true, false).unwrap());
            let url = client_select_provider(&mut client, EnterpriseProvider::WeCom).await;
            let state_hex = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .expect("state parameter")
                .1;
            // The transaction is registered while the callback is pending.
            let state = OAuthState::from_bytes(
                &data_encoding::HEXLOWER
                    .decode(state_hex.as_bytes())
                    .unwrap(),
            )
            .unwrap();
            let entry = registry.take(&state, SystemClock::new().now()).unwrap();
            let session = entry.session();
            registry
                .insert(state, entry, SystemClock::new().now())
                .unwrap();
            // The substream dies with an I/O error instead of a clean
            // close: the exchange propagates it fail-closed.
            fail.store(true, std::sync::atomic::Ordering::SeqCst);
            drop(client);
            session
        };

        let exchange = enterprise_resolve_exchange(
            peer,
            server,
            calls_tx,
            context,
            SystemClock::new(),
            OsSecureRandom,
        );
        let (result, session, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), exchange),
            client_side,
            owner,
        );
        let result = result
            .expect("the exchange must return promptly on the read error")
            .unwrap_err();
        assert!(matches!(result, ProtocolTaskError::Io(_)));
        assert!(registry.is_empty());
        assert!(matches!(
            session.lock().unwrap().phase(),
            EnterpriseResolvePhase::Cancelled
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transaction_guard_frees_the_registry_slot_on_drop() {
        let registry = Arc::new(CallbackRegistry::new());
        let started = MonotonicTime::from_elapsed(Duration::ZERO);
        let mut session = EnterpriseResolveSession::new(RequestId::new(7), locator(), started);
        session.offer_providers().unwrap();
        let state = session
            .select(EnterpriseProvider::WeCom, &mut OsSecureRandom)
            .unwrap();
        let (outcome_tx, _outcome_rx) = oneshot::channel();
        let entry = CallbackEntry::new(
            Arc::new(std::sync::Mutex::new(session)),
            outcome_tx,
            RequestId::new(7),
            started.checked_add(Duration::from_secs(600)).unwrap(),
        );
        registry.insert(state.clone(), entry, started).unwrap();
        assert_eq!(registry.len(), 1);
        {
            let guard = TransactionGuard::new(Arc::clone(&registry), state.clone());
            assert_eq!(registry.len(), 1);
            drop(guard);
        }
        assert!(registry.is_empty());
    }

    // ---- enterprise admission limiters ----

    #[test]
    fn source_table_accepts_sources_up_to_capacity_and_rejects_new_ones() {
        // The source capacity is a fixed constant, so the table is filled
        // with ENTERPRISE_SOURCE_CAPACITY distinct sources and the next
        // new source fails closed while the table is full.
        let mut limiters = EnterpriseLimiters::new();
        let now = MonotonicTime::from_elapsed(Duration::ZERO);
        for index in 0..ENTERPRISE_SOURCE_CAPACITY {
            let source = SourcePrefix::Ipv4(std::net::Ipv4Addr::new(
                10,
                (index >> 8) as u8,
                index as u8,
                1,
            ));
            assert!(
                limiters.check_source(source, now),
                "source {index} admitted"
            );
        }
        assert_eq!(limiters.sources.len(), ENTERPRISE_SOURCE_CAPACITY);
        let overflow = SourcePrefix::Ipv4(std::net::Ipv4Addr::new(10, 255, 255, 2));
        assert!(!limiters.check_source(overflow, now));
        assert_eq!(limiters.sources.len(), ENTERPRISE_SOURCE_CAPACITY);
    }

    #[test]
    fn idle_source_limiters_are_pruned_after_the_idle_window() {
        let mut limiters = EnterpriseLimiters::new();
        let started = MonotonicTime::from_elapsed(Duration::ZERO);
        let old = SourcePrefix::Ipv4("192.0.2.1".parse().unwrap());
        assert!(limiters.check_source(old, started));

        // Within the idle window a check on another source keeps the entry.
        let within = started
            .checked_add(ENTERPRISE_SOURCE_IDLE - Duration::from_secs(1))
            .unwrap();
        let other = SourcePrefix::Ipv4("192.0.2.2".parse().unwrap());
        assert!(limiters.check_source(other, within));
        assert!(limiters.sources.contains_key(&old));

        // Past the idle window the stale entry is pruned on the next check.
        let past = started
            .checked_add(ENTERPRISE_SOURCE_IDLE)
            .unwrap()
            .checked_add(Duration::from_secs(1))
            .unwrap();
        let fresh = SourcePrefix::Ipv4("192.0.2.3".parse().unwrap());
        assert!(limiters.check_source(fresh, past));
        assert!(!limiters.sources.contains_key(&old));
        assert!(limiters.sources.contains_key(&other));
        assert!(limiters.sources.contains_key(&fresh));
    }

    #[test]
    fn admission_retries_when_the_peer_has_no_unique_connection() {
        let mut limiters = EnterpriseLimiters::new();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        // The peer has no established connection at all: the admission
        // cannot be attributed to a source and fails closed with a retry.
        let connections = ConnectionBook::new();
        let decision = handle_enterprise_admission(
            peer,
            &connections,
            &SystemClock::new(),
            &mut limiters,
            RetryAfter::from_millis(250).unwrap(),
        );
        assert!(matches!(decision, Ok(EnterpriseResolveAdmission::Retry(_))));
    }

    #[test]
    fn admission_retries_when_the_source_limiter_is_exhausted() {
        let mut limiters = EnterpriseLimiters::new();
        let started = MonotonicTime::from_elapsed(Duration::ZERO);
        let source = SourcePrefix::Ipv4("192.0.2.1".parse().unwrap());
        // The authentication limiter allows a burst of four; the fifth
        // check on the same source fails. The first check also creates
        // the source entry, so the later checks exercise the existing
        // entry branch of the table.
        for _ in 0..4 {
            assert!(limiters.check_source(source, started));
        }
        assert!(!limiters.check_source(source, started));

        // The global limiter still has capacity, so the admission fails
        // at the per-source check.
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut connections = ConnectionBook::new();
        connections
            .established(
                peer,
                ConnectionId::new_unchecked(1),
                ConnectedPoint::Listener {
                    local_addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                    send_back_addr: "/ip4/192.0.2.1/tcp/1".parse().unwrap(),
                },
            )
            .unwrap();
        let decision = handle_enterprise_admission(
            peer,
            &connections,
            &SystemClock::new(),
            &mut limiters,
            RetryAfter::from_millis(250).unwrap(),
        );
        assert!(matches!(decision, Ok(EnterpriseResolveAdmission::Retry(_))));
    }

    #[test]
    fn global_limiter_fails_closed_after_its_burst() {
        // The authentication rate limit is 1/s with a burst of four.
        let mut limiters = EnterpriseLimiters::new();
        for _ in 0..4 {
            assert!(limiters.global.check());
        }
        assert!(!limiters.global.check());

        // Admission behind the exhausted global limiter fails closed with
        // a retry even for a healthy source.
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut connections = ConnectionBook::new();
        connections
            .established(
                peer,
                ConnectionId::new_unchecked(1),
                ConnectedPoint::Listener {
                    local_addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                    send_back_addr: "/ip4/192.0.2.1/tcp/1".parse().unwrap(),
                },
            )
            .unwrap();
        let decision = handle_enterprise_admission(
            peer,
            &connections,
            &SystemClock::new(),
            &mut limiters,
            RetryAfter::from_millis(250).unwrap(),
        );
        assert!(matches!(decision, Ok(EnterpriseResolveAdmission::Retry(_))));
    }
}
