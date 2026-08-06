//! Enterprise HTTPS callback server for provider browser callbacks.
//!
//! Design section 9: the relay offers one dedicated HTTPS callback
//! listener used only for the WeCom and Feishu callbacks. There is no
//! homepage, admin page, status endpoint or static resource. Result
//! pages are minimal, never cached, and carry no external resources.
//! Callback sessions are handled through the injectable
//! `CallbackHandler`, which owns the single-use state lookup and the
//! bounded member verification.

use crate::enterprise::EnterpriseAuthConfig;
use crate::session::{
    EnterpriseFailure, EnterpriseResolveSession, MemberAdmission, OAuthState, RequestId,
};
use crate::verifier::{
    ExchangeTransport, MAX_AUTHORIZATION_CODE_BYTES, VerifyError, verify_member,
};
use hyper::body::Incoming;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use yonder_core::rate::{DirectRateLimiter, RateLimit};
use yonder_core::{EnterpriseProvider, MonotonicClock, MonotonicTime, SecretDocument};

/// Bound on one callback request query string.
pub const MAX_CALLBACK_QUERY_BYTES: usize = 1024;
/// Bound on the callback state parameter (lowercase hex of 32 bytes).
pub const MAX_CALLBACK_STATE_BYTES: usize = 128;
/// Bound on concurrent callback connections; excess connections fail closed.
pub const MAX_CALLBACK_CONNECTIONS: usize = 16;

/// The outcome of one callback handling run, used for the result page and
/// the redacted logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackResult {
    /// The member was admitted and the session is resolving.
    Admitted,
    /// The user was rejected or the state was already spent.
    Rejected,
    /// The state was missing, malformed or mismatched.
    InvalidState,
    /// The provider exchange failed; nothing can be confirmed.
    Platform,
    /// The callback source exceeded the rate limit.
    Limited,
}

impl CallbackResult {
    /// The redacted result label used in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Rejected => "rejected",
            Self::InvalidState => "invalid-state",
            Self::Platform => "platform",
            Self::Limited => "limited",
        }
    }
}

/// Handles one validated callback request.
///
/// The server validates the path, method, query bounds and encoding before
/// invoking the handler; the handler owns the single-use session lookup,
/// the bounded provider exchange and the redacted logging. The boxed
/// future keeps the trait dyn-compatible for the shared handler.
pub trait CallbackHandler: Send + Sync {
    /// Handles a callback for one provider with the decoded code, state and
    /// source address. The source is used for rate limiting only; it is
    /// never logged.
    fn handle<'a>(
        &'a self,
        provider: EnterpriseProvider,
        code: &'a str,
        state: &'a str,
        source: IpAddr,
    ) -> std::pin::Pin<Box<dyn Future<Output = CallbackResult> + Send + 'a>>;
}

/// The enterprise HTTPS callback server.
#[derive(Clone)]
pub struct CallbackServer {
    acceptor: tokio_rustls::TlsAcceptor,
    listen: std::net::SocketAddr,
}

impl CallbackServer {
    /// Parses the callback TLS material from the validated enterprise
    /// configuration. Any invalid document fails closed at construction.
    pub fn from_config(config: &EnterpriseAuthConfig) -> Result<Self, CallbackServerError> {
        let certificates = parse_certificates(config.certificate_chain())?;
        let private_key = parse_private_key(config.private_key())?;
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|_| CallbackServerError::InvalidTlsMaterial)?;
        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server)),
            listen: config.listen(),
        })
    }

    /// The configured callback listener address.
    #[must_use]
    pub const fn listen(&self) -> std::net::SocketAddr {
        self.listen
    }

    /// Binds the callback listener, reporting the bound address.
    pub async fn bind(&self) -> Result<(TcpListener, std::net::SocketAddr), CallbackServerError> {
        let listener =
            TcpListener::bind(self.listen)
                .await
                .map_err(|source| CallbackServerError::Bind {
                    address: self.listen,
                    source,
                })?;
        let address = listener
            .local_addr()
            .map_err(|source| CallbackServerError::Bind {
                address: self.listen,
                source,
            })?;
        Ok((listener, address))
    }

    /// Serves the callback HTTPS until the shutdown signal completes.
    ///
    /// Connections are accepted until `MAX_CALLBACK_CONNECTIONS`; excess
    /// connections are dropped immediately (fail closed).
    pub async fn serve_on(
        self,
        listener: TcpListener,
        handler: Arc<dyn CallbackHandler>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), CallbackServerError> {
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CALLBACK_CONNECTIONS));
        let mut shutdown = Box::pin(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = listener.accept() => {
                    let (stream, peer) = accepted
                        .map_err(|source| CallbackServerError::Accept { source })?;
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        // The connection capacity is exhausted; fail closed.
                        continue;
                    };
                    let source = peer.ip();
                    let acceptor = self.acceptor.clone();
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let io = hyper_util::rt::TokioIo::new(tls);
                        let service = hyper::service::service_fn(move |request| {
                            handle_request(Arc::clone(&handler), request, source)
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, service)
                        .await;
                    });
                }
            }
        }
    }
}

/// Parses one or more DER certificates or PEM bundles into a leaf-first chain.
fn parse_certificates(
    documents: &[SecretDocument],
) -> Result<Vec<CertificateDer<'static>>, CallbackServerError> {
    let mut certificates = Vec::new();
    for document in documents {
        let bytes = document.as_bytes();
        if contains_pem_marker(bytes) {
            for item in CertificateDer::pem_slice_iter(bytes) {
                certificates.push(item.map_err(|_| CallbackServerError::InvalidCertificate)?);
            }
        } else {
            certificates.push(CertificateDer::from(bytes.to_vec()));
        }
    }
    if certificates.is_empty() {
        return Err(CallbackServerError::InvalidCertificate);
    }
    Ok(certificates)
}

/// Parses a DER or PEM private key document.
fn parse_private_key(
    document: &SecretDocument,
) -> Result<PrivateKeyDer<'static>, CallbackServerError> {
    let bytes = document.as_bytes();
    if contains_pem_marker(bytes) {
        PrivateKeyDer::from_pem_slice(bytes).map_err(|_| CallbackServerError::InvalidPrivateKey)
    } else {
        PrivateKeyDer::try_from(bytes.to_vec()).map_err(|_| CallbackServerError::InvalidPrivateKey)
    }
}

fn contains_pem_marker(document: &[u8]) -> bool {
    document
        .windows(b"-----BEGIN".len())
        .any(|window| window == b"-----BEGIN")
}

/// Dispatches one callback request: exact path match, GET only, bounded
/// query, then the handler. Every other request gets a minimal response.
async fn handle_request(
    handler: Arc<dyn CallbackHandler>,
    request: hyper::Request<Incoming>,
    source: IpAddr,
) -> Result<hyper::Response<String>, io::Error> {
    let provider = match request.uri().path() {
        "/yonder/callback/wecom" => Some(EnterpriseProvider::WeCom),
        "/yonder/callback/feishu" => Some(EnterpriseProvider::Feishu),
        _ => None,
    };
    let Some(provider) = provider else {
        return Ok(response::not_found());
    };
    if request.method() != hyper::Method::GET {
        return Ok(response::method_not_allowed());
    }
    let Some(query) = request.uri().query() else {
        log_rejected(provider, "missing-query");
        return Ok(response::bad_request());
    };
    if query.len() > MAX_CALLBACK_QUERY_BYTES {
        log_rejected(provider, "oversized-query");
        return Ok(response::bad_request());
    }
    let Some(code) = query_param(query, "code") else {
        log_rejected(provider, "missing-code");
        return Ok(response::bad_request());
    };
    let Some(state) = query_param(query, "state") else {
        log_rejected(provider, "missing-state");
        return Ok(response::bad_request());
    };
    let Some(code) = decode_param(code) else {
        log_rejected(provider, "invalid-code");
        return Ok(response::bad_request());
    };
    let Some(state) = decode_param(state) else {
        log_rejected(provider, "invalid-state");
        return Ok(response::bad_request());
    };
    if code.is_empty()
        || code.len() > MAX_AUTHORIZATION_CODE_BYTES
        || state.is_empty()
        || state.len() > MAX_CALLBACK_STATE_BYTES
    {
        log_rejected(provider, "oversized-parameter");
        return Ok(response::bad_request());
    }
    let result = handler.handle(provider, &code, &state, source).await;
    Ok(response::result(result))
}

/// Extracts one raw query parameter by name.
fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .and_then(|(k, v)| (k == key).then_some(v))
    })
}

/// Decodes a percent-encoded query value; `+` decodes as space.
fn decode_param(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut bytes = value.as_bytes().iter();
    while let Some(&byte) = bytes.next() {
        match byte {
            b'%' => {
                let hi = hex_digit(*bytes.next()?)?;
                let lo = hex_digit(*bytes.next()?)?;
                decoded.push(char::from(hi << 4 | lo));
            }
            b'+' => decoded.push(' '),
            byte => decoded.push(char::from(byte)),
        }
    }
    Some(decoded)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Redacted callback rejection logging: platform and reason only.
fn log_rejected(provider: EnterpriseProvider, reason: &str) {
    tracing::info!(
        event = "enterprise_callback_rejected",
        platform = provider.as_str(),
        phase = "callback",
        result = reason,
        "enterprise callback rejected"
    );
}

mod response {
    use super::CallbackResult;
    use hyper::Response;

    /// The minimal result page: inline only, no cache, no external resources.
    fn page(status: hyper::StatusCode, text: &str) -> Response<String> {
        let body = format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\"><title>Yonder</title></head><body><p>{text}</p></body></html>"
        );
        Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(hyper::header::CACHE_CONTROL, "no-store")
            .body(body)
            .expect("static result page cannot fail to build")
    }

    pub(super) fn result(result: CallbackResult) -> Response<String> {
        match result {
            CallbackResult::Admitted => {
                page(hyper::StatusCode::OK, "认证成功，请返回 Yonder 客户端")
            }
            CallbackResult::Rejected => {
                page(hyper::StatusCode::OK, "认证未通过，请返回 Yonder 客户端")
            }
            CallbackResult::InvalidState => page(
                hyper::StatusCode::BAD_REQUEST,
                "请求无效，请返回 Yonder 客户端重新发起",
            ),
            CallbackResult::Platform => page(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "认证暂不可用，请稍后重试",
            ),
            CallbackResult::Limited => page(
                hyper::StatusCode::TOO_MANY_REQUESTS,
                "请求过于频繁，请稍后重试",
            ),
        }
    }

    pub(super) fn bad_request() -> Response<String> {
        page(hyper::StatusCode::BAD_REQUEST, "请求无效")
    }

    pub(super) fn method_not_allowed() -> Response<String> {
        page(hyper::StatusCode::METHOD_NOT_ALLOWED, "请求无效")
    }

    pub(super) fn not_found() -> Response<String> {
        page(hyper::StatusCode::NOT_FOUND, "请求无效")
    }
}

/// One authenticating callback transaction: the shared session, the
/// completion signal the resolve handler awaits, and the redacted log
/// fields copied at registration.
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

/// Callback server failures; every variant fails closed.
#[derive(Debug, Error)]
pub enum CallbackServerError {
    #[error("the enterprise callback certificate chain is invalid")]
    InvalidCertificate,
    #[error("the enterprise callback private key is invalid")]
    InvalidPrivateKey,
    #[error("the enterprise callback TLS material is invalid")]
    InvalidTlsMaterial,
    #[error("failed to bind the callback listener {address}: {source}")]
    Bind {
        address: std::net::SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("the callback listener failed: {source}")]
    Accept {
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CallbackHandler, CallbackResult, CallbackServer, CallbackServerError,
        MAX_CALLBACK_QUERY_BYTES, decode_param, query_param,
    };
    use crate::enterprise::{CallbackExternalUrl, EnterpriseAuthConfig, ProviderSecrets};
    use crate::session::{EnterpriseResolveSession, OAuthState, RequestId};
    use std::net::IpAddr;
    use std::sync::Arc;
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::CertificateDer;
    use url::Url;
    use yonder_core::{EnterpriseProvider, EnterpriseProviders, SecretDocument};

    const TEST_CERT_DER: &[u8] = include_bytes!("../../yon/tests/fixtures/localhost-test-cert.der");
    const TEST_KEY_DER: &[u8] = include_bytes!("../../yon/tests/fixtures/localhost-test-key.der");

    #[derive(Clone, Copy)]
    struct StubHandler(CallbackResult);

    impl CallbackHandler for StubHandler {
        fn handle<'a>(
            &'a self,
            _provider: EnterpriseProvider,
            _code: &'a str,
            _state: &'a str,
            _source: std::net::IpAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CallbackResult> + Send + 'a>>
        {
            let result = self.0;
            Box::pin(async move { result })
        }
    }

    fn server_with(listen: std::net::SocketAddr) -> CallbackServer {
        let providers = EnterpriseProviders::new(true, false).unwrap();
        let secrets = ProviderSecrets::new(
            providers,
            Some(std::path::PathBuf::from("wecom.secret")),
            None,
        )
        .unwrap();
        let config = EnterpriseAuthConfig::new(
            listen,
            CallbackExternalUrl::new(Url::parse("https://relay.example.test").unwrap()).unwrap(),
            vec![SecretDocument::new(TEST_CERT_DER.to_vec())],
            SecretDocument::new(TEST_KEY_DER.to_vec()),
            providers,
            secrets,
        )
        .unwrap();
        CallbackServer::from_config(&config).unwrap()
    }

    /// Executes one HTTP/1.1 request over a TLS connection trusting the
    /// fixture CA, and returns the status line and headers.
    async fn tls_request(address: std::net::SocketAddr, request: &str) -> (String, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut roots = rustls::RootCertStore::empty();
        let ca = include_bytes!("../../yon/tests/fixtures/localhost-test-ca.der");
        roots
            .add(CertificateDer::from(ca.to_vec()))
            .expect("fixture CA is parseable");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        tls.read_to_end(&mut bytes).await.unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let mut lines = text.lines();
        let status = lines.next().unwrap_or_default().to_owned();
        let headers: Vec<&str> = lines.take_while(|line| !line.is_empty()).collect();
        (status, headers.join("\n"))
    }

    #[test]
    fn query_params_decode_bounded_and_missing() {
        assert_eq!(query_param("code=a&state=b", "code"), Some("a"));
        assert_eq!(query_param("code=a&state=b", "state"), Some("b"));
        assert_eq!(query_param("state=b", "code"), None);
        assert_eq!(decode_param("a%20b"), Some("a b".to_owned()));
        assert_eq!(decode_param("a+b"), Some("a b".to_owned()));
        assert_eq!(decode_param("a%2Fb"), Some("a/b".to_owned()));
        assert_eq!(decode_param("a%zz"), None);
        assert_eq!(decode_param("a%1"), None);
    }

    use crate::callback::{
        CallbackEntry, CallbackRegistry, CallbackRegistryError, CallbackSessionHandler,
        decode_state,
    };
    use crate::provider::{ProviderCredentials, ProviderField, SecretText, WeComCredentials};
    use crate::session::EnterpriseResolvePhase;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::oneshot;
    use yonder_core::{Locator, MonotonicClock, MonotonicTime, OsSecureRandom};

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

    #[test]
    fn invalid_tls_material_fails_closed_at_construction() {
        let config = EnterpriseAuthConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            CallbackExternalUrl::new(Url::parse("https://relay.example.test").unwrap()).unwrap(),
            vec![SecretDocument::new(vec![1, 2, 3])],
            SecretDocument::new(TEST_KEY_DER.to_vec()),
            EnterpriseProviders::new(true, false).unwrap(),
            ProviderSecrets::new(
                EnterpriseProviders::new(true, false).unwrap(),
                Some(std::path::PathBuf::from("wecom.secret")),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            CallbackServer::from_config(&config),
            Err(CallbackServerError::InvalidTlsMaterial)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn callback_requests_are_served_over_https() {
        let server = server_with("127.0.0.1:0".parse().unwrap());
        let (listener, address) = server.bind().await.unwrap();
        let handler: Arc<dyn CallbackHandler> = Arc::new(StubHandler(CallbackResult::Admitted));
        let serving = tokio::spawn(server.serve_on(listener, handler, std::future::pending()));
        let (status, headers) = tls_request(
            address,
            "GET /yonder/callback/wecom?code=auth-code-1&state=abcdef HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert!(headers.to_lowercase().contains("cache-control: no-store"));
        assert!(headers.to_lowercase().contains("content-type: text/html"));
        serving.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_paths_methods_and_missing_params_are_rejected() {
        let server = server_with("127.0.0.1:0".parse().unwrap());
        let (listener, address) = server.bind().await.unwrap();
        let handler: Arc<dyn CallbackHandler> = Arc::new(StubHandler(CallbackResult::Rejected));
        let serving = tokio::spawn(server.serve_on(listener, handler, std::future::pending()));
        for request in [
            "GET / HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
            "GET /yonder/callback/wecom HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
            "GET /yonder/callback/wecom?code=a HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
            "POST /yonder/callback/wecom?code=a&state=b HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
        ] {
            let (status, _) = tls_request(address, request).await;
            assert!(
                status.starts_with("HTTP/1.1 400")
                    || status.starts_with("HTTP/1.1 404")
                    || status.starts_with("HTTP/1.1 405"),
                "{status}"
            );
        }
        serving.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_queries_are_rejected() {
        let server = server_with("127.0.0.1:0".parse().unwrap());
        let (listener, address) = server.bind().await.unwrap();
        let handler: Arc<dyn CallbackHandler> = Arc::new(StubHandler(CallbackResult::Admitted));
        let serving = tokio::spawn(server.serve_on(listener, handler, std::future::pending()));
        let big = format!(
            "GET /yonder/callback/wecom?code={}&state=x HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
            "a".repeat(MAX_CALLBACK_QUERY_BYTES)
        );
        let (status, _) = tls_request(address, &big).await;
        assert!(status.starts_with("HTTP/1.1 400"), "{status}");
        serving.abort();
    }

    #[test]
    fn result_pages_map_every_outcome_to_minimal_never_cached_responses() {
        use crate::callback::response::result;
        let cases = [
            (CallbackResult::Admitted, "200"),
            (CallbackResult::Rejected, "200"),
            (CallbackResult::InvalidState, "400"),
            (CallbackResult::Platform, "503"),
            (CallbackResult::Limited, "429"),
        ];
        for (outcome, status) in cases {
            let response = result(outcome);
            assert_eq!(response.status().as_str(), status, "{outcome:?}");
            assert_eq!(
                response
                    .headers()
                    .get(hyper::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store"),
                "{outcome:?}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("text/html; charset=utf-8"),
                "{outcome:?}"
            );
            let body = response.body();
            assert!(body.contains("Yonder"), "{outcome:?}");
            assert!(
                !body.contains("http"),
                "{outcome:?} has no external resources"
            );
        }
    }
}
