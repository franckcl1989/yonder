//! Bounded Axum HTTPS callback service for enterprise authorization.

use crate::enterprise::EnterpriseAuthConfig;
use crate::verifier::MAX_AUTHORIZATION_CODE_BYTES;
use axum::Router;
use axum::extract::{ConnectInfo, RawQuery, State, connect_info::Connected};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use axum_server::{AddrListener, Address, Handle, Server};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Host;
use yonder_core::EnterpriseProvider;
use yonder_net::contains_pem_marker;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CALLBACK_QUERY_BYTES: usize = 1024;
pub const MAX_CALLBACK_STATE_BYTES: usize = 43;
pub const MAX_CALLBACK_CONNECTIONS: usize = 16;
const CALLBACK_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackResult {
    Admitted,
    Rejected,
    InvalidState,
    Platform,
    Limited,
}

impl CallbackResult {
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

/// The provider outcome carried by one syntactically valid callback.
/// Raw provider errors and descriptions never cross this boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CallbackAuthorization<'a> {
    Code(&'a str),
    Denied,
    ProviderFailed,
}

impl fmt::Debug for CallbackAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(_) => formatter.write_str("CallbackAuthorization::Code([REDACTED])"),
            Self::Denied => formatter.write_str("CallbackAuthorization::Denied"),
            Self::ProviderFailed => formatter.write_str("CallbackAuthorization::ProviderFailed"),
        }
    }
}

pub trait CallbackHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        provider: EnterpriseProvider,
        authorization: CallbackAuthorization<'a>,
        state: &'a str,
        source: IpAddr,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = CallbackResult> + Send + 'a>>;
}

/// Prepared callback TLS configuration. Binding remains explicit so relay
/// startup fails before entering the network event loop.
#[derive(Clone)]
pub struct CallbackServer {
    tls: RustlsConfig,
    listen: SocketAddr,
}

impl fmt::Debug for CallbackServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackServer")
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

impl CallbackServer {
    /// Parses and validates callback TLS without binding the configured port.
    /// Both `config check` and the serving path use this exact preflight.
    pub fn preflight(config: &EnterpriseAuthConfig) -> Result<Self, CallbackServerError> {
        crate::exchange::install_ring_crypto_provider()
            .map_err(|_| CallbackServerError::CryptoProvider)?;
        let certificate_documents = config
            .certificate_chain()
            .iter()
            .map(|document| document.as_bytes())
            .collect::<Vec<_>>();
        let certificates_are_pem = certificate_documents
            .iter()
            .all(|document| contains_pem_marker(document));
        let certificates_are_der = certificate_documents
            .iter()
            .all(|document| !contains_pem_marker(document));
        let key_is_pem = contains_pem_marker(config.private_key().as_bytes());

        let (certificates, private_key) = if certificates_are_pem && key_is_pem {
            (
                parse_pem_certificates(&certificate_documents)?,
                parse_pem_private_key(config.private_key().as_bytes())?,
            )
        } else if certificates_are_der && !key_is_pem {
            (
                certificate_documents
                    .into_iter()
                    .map(|document| rustls::pki_types::CertificateDer::from(document.to_vec()))
                    .collect(),
                rustls::pki_types::PrivateKeyDer::try_from(
                    config.private_key().as_bytes().to_vec(),
                )
                .map_err(|_| CallbackServerError::InvalidTlsPrivateKey)?,
            )
        } else {
            return Err(CallbackServerError::MixedTlsEncoding);
        };

        for certificate in &certificates {
            rustls::server::ParsedCertificate::try_from(certificate)
                .map_err(CallbackServerError::InvalidTlsCertificate)?;
        }

        let server_name = match config.callback_url().host() {
            Some(Host::Domain(host)) => rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| CallbackServerError::InvalidCallbackHost)?,
            Some(Host::Ipv4(address)) => rustls::pki_types::ServerName::from(address),
            Some(Host::Ipv6(address)) => rustls::pki_types::ServerName::from(address),
            None => return Err(CallbackServerError::InvalidCallbackHost),
        };
        let leaf = certificates
            .first()
            .ok_or(CallbackServerError::InvalidTlsCertificateChain)?;
        let parsed_leaf = rustls::server::ParsedCertificate::try_from(leaf)
            .map_err(CallbackServerError::InvalidTlsCertificate)?;
        rustls::client::verify_server_name(&parsed_leaf, &server_name)
            .map_err(CallbackServerError::CallbackCertificateName)?;

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|error| match error {
                rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch) => {
                    CallbackServerError::TlsKeyMismatch
                }
                source => CallbackServerError::InvalidTlsPrivateKeyMaterial(source),
            })?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            tls: RustlsConfig::from_config(Arc::new(tls)),
            listen: config.listen(),
        })
    }

    pub async fn from_config(config: &EnterpriseAuthConfig) -> Result<Self, CallbackServerError> {
        Self::preflight(config)
    }

    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) async fn bind(&self) -> Result<(LimitedListener, SocketAddr), CallbackServerError> {
        let listener =
            TcpListener::bind(self.listen)
                .await
                .map_err(|source| CallbackServerError::Bind {
                    address: self.listen,
                    source,
                })?;
        let bound = listener
            .local_addr()
            .map_err(|source| CallbackServerError::Bind {
                address: self.listen,
                source,
            })?;
        Ok((LimitedListener::new(listener), bound))
    }

    pub(crate) async fn serve_on(
        self,
        listener: LimitedListener,
        handler: Arc<dyn CallbackHandler>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), CallbackServerError> {
        let state = CallbackState { handler };
        let app = Router::new()
            .route("/yonder/callback/wecom", get(wecom_callback))
            .route("/yonder/callback/feishu", get(feishu_callback))
            .method_not_allowed_fallback(method_not_allowed)
            .fallback(not_found)
            .with_state(state);

        let handle: Handle<LimitedAddress> = Handle::new();
        let acceptor = RustlsAcceptor::new(self.tls).handshake_timeout(CALLBACK_CONNECTION_TIMEOUT);
        let mut server = Server::from_listener(listener)
            .acceptor(acceptor)
            .http1_only()
            .handle(handle.clone());
        server.http_builder().http1().keep_alive(false);
        let serving = server.serve(app.into_make_service_with_connect_info::<CallbackSource>());
        tokio::pin!(serving);
        tokio::pin!(shutdown);
        tokio::select! {
            result = &mut serving => result.map_err(|source| CallbackServerError::Serve { source }),
            () = &mut shutdown => {
                handle.graceful_shutdown(Some(CALLBACK_CONNECTION_TIMEOUT));
                serving
                    .await
                    .map_err(|source| CallbackServerError::Serve { source })
            }
        }
    }
}

fn parse_pem_certificates(
    documents: &[&[u8]],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, CallbackServerError> {
    use rustls::pki_types::pem::{SectionKind, SliceIter};

    let mut certificates = Vec::new();
    for document in documents {
        let initial_count = certificates.len();
        for section in SliceIter::<(SectionKind, Vec<u8>)>::new(document) {
            let (kind, certificate) =
                section.map_err(|_| CallbackServerError::InvalidTlsCertificatePem)?;
            if kind != SectionKind::Certificate {
                return Err(CallbackServerError::InvalidTlsCertificatePem);
            }
            certificates.push(rustls::pki_types::CertificateDer::from(certificate));
        }
        if certificates.len() == initial_count {
            return Err(CallbackServerError::InvalidTlsCertificatePem);
        }
    }
    Ok(certificates)
}

fn parse_pem_private_key(
    document: &[u8],
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, CallbackServerError> {
    use rustls::pki_types::pem::{SectionKind, SliceIter};

    let mut private_key = None;
    for section in SliceIter::<(SectionKind, Vec<u8>)>::new(document) {
        let (kind, key) = section.map_err(|_| CallbackServerError::InvalidTlsPrivateKeyPem)?;
        if !matches!(
            kind,
            SectionKind::RsaPrivateKey | SectionKind::PrivateKey | SectionKind::EcPrivateKey
        ) || private_key.is_some()
        {
            return Err(CallbackServerError::InvalidTlsPrivateKeyPem);
        }
        private_key = Some(
            rustls::pki_types::PrivateKeyDer::try_from(key)
                .map_err(|_| CallbackServerError::InvalidTlsPrivateKey)?,
        );
    }
    private_key.ok_or(CallbackServerError::InvalidTlsPrivateKeyPem)
}

#[derive(Clone)]
struct CallbackState {
    handler: Arc<dyn CallbackHandler>,
}

#[derive(Debug, Clone, Copy)]
struct CallbackSource {
    ip: IpAddr,
    deadline: tokio::time::Instant,
}

impl Connected<LimitedAddress> for CallbackSource {
    fn connect_info(address: LimitedAddress) -> Self {
        Self {
            ip: address.socket.ip(),
            deadline: address.deadline,
        }
    }
}

async fn wecom_callback(
    state: State<CallbackState>,
    source: ConnectInfo<CallbackSource>,
    query: RawQuery,
) -> Response {
    dispatch(EnterpriseProvider::WeCom, state, source, query).await
}

async fn feishu_callback(
    state: State<CallbackState>,
    source: ConnectInfo<CallbackSource>,
    query: RawQuery,
) -> Response {
    dispatch(EnterpriseProvider::Feishu, state, source, query).await
}

async fn dispatch(
    provider: EnterpriseProvider,
    State(state): State<CallbackState>,
    ConnectInfo(source): ConnectInfo<CallbackSource>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(mut query) = query else {
        log_rejected(provider, "missing-query");
        return response::bad_request();
    };
    if query.len() > MAX_CALLBACK_QUERY_BYTES {
        query.zeroize();
        log_rejected(provider, "oversized-query");
        return response::bad_request();
    }
    let parsed = parse_callback_query(&query);
    query.zeroize();
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            log_rejected(provider, error.as_str());
            return response::bad_request();
        }
    };
    let authorization = match &parsed.authorization {
        ParsedAuthorization::Code(code) => CallbackAuthorization::Code(code.as_str()),
        ParsedAuthorization::Denied => CallbackAuthorization::Denied,
        ParsedAuthorization::ProviderFailed => CallbackAuthorization::ProviderFailed,
    };

    let handled = tokio::time::timeout_at(
        source.deadline,
        state.handler.handle(
            provider,
            authorization,
            parsed.state.as_str(),
            source.ip,
            source.deadline,
        ),
    )
    .await
    .unwrap_or(CallbackResult::Platform);
    response::result(handled)
}

struct ParsedCallbackQuery {
    authorization: ParsedAuthorization,
    state: Zeroizing<String>,
}

enum ParsedAuthorization {
    Code(CallbackCode),
    Denied,
    ProviderFailed,
}

struct CallbackCode(Zeroizing<String>);

impl CallbackCode {
    fn new(code: Zeroizing<String>) -> Self {
        Self(code)
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for CallbackCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallbackCode([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackQueryError {
    InvalidEncoding,
    DuplicateParameter,
    MissingState,
    InvalidState,
    InvalidOutcome,
    InvalidCode,
}

impl CallbackQueryError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "invalid-encoding",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::MissingState => "missing-state",
            Self::InvalidState => "invalid-state",
            Self::InvalidOutcome => "invalid-outcome",
            Self::InvalidCode => "invalid-code",
        }
    }
}

fn parse_callback_query(query: &str) -> Result<ParsedCallbackQuery, CallbackQueryError> {
    if !valid_percent_encoding(query.as_bytes()) {
        return Err(CallbackQueryError::InvalidEncoding);
    }

    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    let mut error_uri = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let slot = match name.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
            "error_description" => &mut error_description,
            "error_uri" => &mut error_uri,
            _ => continue,
        };
        if slot.replace(Zeroizing::new(value.into_owned())).is_some() {
            return Err(CallbackQueryError::DuplicateParameter);
        }
    }

    let state = state.ok_or(CallbackQueryError::MissingState)?;
    if state.len() != MAX_CALLBACK_STATE_BYTES {
        return Err(CallbackQueryError::InvalidState);
    }

    let authorization = match (code, error) {
        (Some(code), None) if error_description.is_none() && error_uri.is_none() => {
            if code.is_empty() || code.len() > MAX_AUTHORIZATION_CODE_BYTES {
                return Err(CallbackQueryError::InvalidCode);
            }
            ParsedAuthorization::Code(CallbackCode::new(code))
        }
        (None, Some(error)) if !error.is_empty() => {
            if error.as_str() == "access_denied" {
                ParsedAuthorization::Denied
            } else {
                ParsedAuthorization::ProviderFailed
            }
        }
        _ => return Err(CallbackQueryError::InvalidOutcome),
    };
    Ok(ParsedCallbackQuery {
        authorization,
        state,
    })
}

fn valid_percent_encoding(query: &[u8]) -> bool {
    let mut index = 0;
    while index < query.len() {
        if query[index] == b'%' {
            if index + 2 >= query.len()
                || !query[index + 1].is_ascii_hexdigit()
                || !query[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn log_rejected(provider: EnterpriseProvider, reason: &str) {
    tracing::info!(
        event = "enterprise_callback_rejected",
        platform = provider.as_str(),
        phase = "callback",
        result = reason,
        "enterprise callback rejected"
    );
}

async fn method_not_allowed() -> Response {
    response::method_not_allowed()
}

async fn not_found() -> Response {
    response::not_found()
}

mod response {
    use super::{CallbackResult, Html, IntoResponse, Response, StatusCode};

    fn page(status: StatusCode, text: &'static str) -> Response {
        let body = format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\"><title>Yonder</title></head><body><p>{text}</p></body></html>"
        );
        (
            status,
            [
                ("cache-control", "no-store"),
                ("content-security-policy", "default-src 'none'"),
                ("x-content-type-options", "nosniff"),
            ],
            Html(body),
        )
            .into_response()
    }

    pub(super) fn result(result: CallbackResult) -> Response {
        match result {
            CallbackResult::Admitted => page(StatusCode::OK, "认证成功，请返回 Yonder 客户端"),
            CallbackResult::Rejected => page(StatusCode::OK, "认证未通过，请返回 Yonder 客户端"),
            CallbackResult::InvalidState => page(
                StatusCode::BAD_REQUEST,
                "请求无效，请返回 Yonder 客户端重新发起",
            ),
            CallbackResult::Platform => {
                page(StatusCode::SERVICE_UNAVAILABLE, "认证暂不可用，请稍后重试")
            }
            CallbackResult::Limited => {
                page(StatusCode::TOO_MANY_REQUESTS, "请求过于频繁，请稍后重试")
            }
        }
    }

    pub(super) fn bad_request() -> Response {
        page(StatusCode::BAD_REQUEST, "请求无效")
    }

    pub(super) fn method_not_allowed() -> Response {
        page(StatusCode::METHOD_NOT_ALLOWED, "请求无效")
    }

    pub(super) fn not_found() -> Response {
        page(StatusCode::NOT_FOUND, "请求无效")
    }
}

/// Address wrapper carrying the callback connection capacity.
#[derive(Clone)]
struct LimitedAddress {
    socket: SocketAddr,
    permits: Arc<Semaphore>,
    deadline: tokio::time::Instant,
}

impl fmt::Debug for LimitedAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LimitedAddress")
            .field(&self.socket)
            .finish()
    }
}

impl Address for LimitedAddress {
    type Stream = LimitedStream;
    type Listener = LimitedListener;
}

pub(crate) struct LimitedListener {
    inner: TcpListener,
    permits: Arc<Semaphore>,
}

impl fmt::Debug for LimitedListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LimitedListener")
            .field("local_addr", &self.inner.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl LimitedListener {
    fn new(inner: TcpListener) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(MAX_CALLBACK_CONNECTIONS)),
        }
    }
}

impl AddrListener<LimitedStream, LimitedAddress> for LimitedListener {
    async fn bind_to(address: LimitedAddress) -> io::Result<Self> {
        Ok(Self {
            inner: TcpListener::bind(address.socket).await?,
            permits: address.permits,
        })
    }

    async fn accept_stream(&self) -> io::Result<(LimitedStream, LimitedAddress)> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("callback connection limiter closed"))?;
        let (stream, socket) = self.inner.accept().await?;
        let deadline = tokio::time::Instant::now() + CALLBACK_CONNECTION_TIMEOUT;
        let address = LimitedAddress {
            socket,
            permits: Arc::clone(&self.permits),
            deadline,
        };
        Ok((LimitedStream::new(stream, permit, deadline), address))
    }

    fn get_local_addr(&self) -> io::Result<LimitedAddress> {
        Ok(LimitedAddress {
            socket: self.inner.local_addr()?,
            permits: Arc::clone(&self.permits),
            deadline: tokio::time::Instant::now() + CALLBACK_CONNECTION_TIMEOUT,
        })
    }
}

struct LimitedStream {
    inner: TcpStream,
    deadline: Pin<Box<tokio::time::Sleep>>,
    _permit: OwnedSemaphorePermit,
}

impl LimitedStream {
    fn new(inner: TcpStream, permit: OwnedSemaphorePermit, deadline: tokio::time::Instant) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            _permit: permit,
        }
    }

    fn check_deadline(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if self.deadline.as_mut().poll(context).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "callback connection timed out",
            ))
        } else {
            Ok(())
        }
    }
}

impl AsyncRead for LimitedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for LimitedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.check_deadline(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Debug, Error)]
pub enum CallbackServerError {
    #[error("failed to install the enterprise callback TLS crypto provider")]
    CryptoProvider,
    #[error("the enterprise callback certificate chain is empty")]
    InvalidTlsCertificateChain,
    #[error("the enterprise callback certificate PEM is invalid")]
    InvalidTlsCertificatePem,
    #[error("the enterprise callback certificate is invalid: {0}")]
    InvalidTlsCertificate(#[source] rustls::Error),
    #[error("the enterprise callback private key PEM is invalid")]
    InvalidTlsPrivateKeyPem,
    #[error("the enterprise callback private key encoding is invalid")]
    InvalidTlsPrivateKey,
    #[error("the enterprise callback certificate and private key must use the same encoding")]
    MixedTlsEncoding,
    #[error("the enterprise callback certificate and private key do not match")]
    TlsKeyMismatch,
    #[error("the enterprise callback private key material is invalid: {0}")]
    InvalidTlsPrivateKeyMaterial(#[source] rustls::Error),
    #[error("the enterprise callback URL host is not a valid TLS server name")]
    InvalidCallbackHost,
    #[error("the enterprise callback certificate SAN does not match the callback URL host: {0}")]
    CallbackCertificateName(#[source] rustls::Error),
    #[error("failed to bind the callback listener {address}: {source}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("the callback listener failed: {source}")]
    Serve {
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CALLBACK_CONNECTION_TIMEOUT, CallbackAuthorization, CallbackHandler, CallbackQueryError,
        CallbackResult, CallbackServer, CallbackServerError, CallbackSource, CallbackState,
        LimitedAddress, LimitedListener, MAX_CALLBACK_CONNECTIONS, MAX_CALLBACK_QUERY_BYTES,
        MAX_CALLBACK_STATE_BYTES, ParsedAuthorization, dispatch, parse_callback_query,
        parse_pem_certificates,
    };
    use crate::enterprise::{CallbackExternalUrl, EnterpriseAuthConfig, ProviderSecrets};
    use axum::extract::{ConnectInfo, RawQuery, State, connect_info::Connected as _};
    use axum_server::AddrListener as _;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Semaphore;
    use url::Url;
    use yonder_core::{EnterpriseProvider, EnterpriseProviders, SecretDocument};

    const TEST_CERT_DER: &[u8] = include_bytes!("../../yon/tests/fixtures/localhost-test-cert.der");
    const TEST_KEY_DER: &[u8] = include_bytes!("../../yon/tests/fixtures/localhost-test-key.der");
    const TEST_MISMATCHED_KEY_DER: &[u8] =
        include_bytes!("../../yon/tests/fixtures/localhost-self-signed-key.der");
    const TEST_CA_DER: &[u8] = include_bytes!("../../yon/tests/fixtures/localhost-test-ca.der");
    const VALID_STATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    struct RoutingHandler;

    impl CallbackHandler for RoutingHandler {
        fn handle<'a>(
            &'a self,
            _provider: EnterpriseProvider,
            authorization: CallbackAuthorization<'a>,
            _state: &'a str,
            _source: std::net::IpAddr,
            _deadline: tokio::time::Instant,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CallbackResult> + Send + 'a>>
        {
            let result = match authorization {
                CallbackAuthorization::Code("admitted") => CallbackResult::Admitted,
                CallbackAuthorization::Code("rejected") | CallbackAuthorization::Denied => {
                    CallbackResult::Rejected
                }
                CallbackAuthorization::Code("invalid-state") => CallbackResult::InvalidState,
                CallbackAuthorization::Code("platform") | CallbackAuthorization::ProviderFailed => {
                    CallbackResult::Platform
                }
                CallbackAuthorization::Code("limited") => CallbackResult::Limited,
                CallbackAuthorization::Code(_) => CallbackResult::Rejected,
            };
            Box::pin(std::future::ready(result))
        }
    }

    struct PendingHandler;

    impl CallbackHandler for PendingHandler {
        fn handle<'a>(
            &'a self,
            _provider: EnterpriseProvider,
            _authorization: CallbackAuthorization<'a>,
            _state: &'a str,
            _source: std::net::IpAddr,
            _deadline: tokio::time::Instant,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CallbackResult> + Send + 'a>>
        {
            Box::pin(std::future::pending())
        }
    }

    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        let encoded = data_encoding::BASE64.encode(der);
        let mut document = format!("-----BEGIN {label}-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            document.push_str(std::str::from_utf8(chunk).unwrap());
            document.push('\n');
        }
        document.push_str(&format!("-----END {label}-----\n"));
        document.into_bytes()
    }

    fn config_with(
        listen: std::net::SocketAddr,
        certificates: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> EnterpriseAuthConfig {
        config_with_url(listen, "https://localhost.", certificates, private_key)
    }

    fn config_with_url(
        listen: std::net::SocketAddr,
        callback_url: &str,
        certificates: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> EnterpriseAuthConfig {
        let providers = EnterpriseProviders::new(true, false).unwrap();
        let secrets = ProviderSecrets::new(
            providers,
            Some(std::path::PathBuf::from("wecom.secret")),
            None,
        )
        .unwrap();
        EnterpriseAuthConfig::new(
            listen,
            CallbackExternalUrl::new(Url::parse(callback_url).unwrap()).unwrap(),
            certificates.into_iter().map(SecretDocument::new).collect(),
            SecretDocument::new(private_key),
            providers,
            secrets,
        )
        .unwrap()
    }

    async fn server_with(listen: std::net::SocketAddr) -> CallbackServer {
        let config = config_with(listen, vec![TEST_CERT_DER.to_vec()], TEST_KEY_DER.to_vec());
        CallbackServer::from_config(&config).await.unwrap()
    }

    #[test]
    fn callback_results_query_parser_and_capacity_have_the_frozen_values() {
        assert_eq!(MAX_CALLBACK_CONNECTIONS, 16);
        assert_eq!(MAX_CALLBACK_QUERY_BYTES, 1024);
        assert_eq!(MAX_CALLBACK_STATE_BYTES, 43);
        assert_eq!(CALLBACK_CONNECTION_TIMEOUT, Duration::from_secs(10));
        for (result, text) in [
            (CallbackResult::Admitted, "admitted"),
            (CallbackResult::Rejected, "rejected"),
            (CallbackResult::InvalidState, "invalid-state"),
            (CallbackResult::Platform, "platform"),
            (CallbackResult::Limited, "limited"),
        ] {
            assert_eq!(result.as_str(), text);
        }
        assert!(
            !format!("{:?}", CallbackAuthorization::Code("sensitive-code"))
                .contains("sensitive-code")
        );
        assert_eq!(
            format!("{:?}", CallbackAuthorization::Denied),
            "CallbackAuthorization::Denied"
        );
        assert_eq!(
            format!("{:?}", CallbackAuthorization::ProviderFailed),
            "CallbackAuthorization::ProviderFailed"
        );
        assert_eq!(
            CallbackQueryError::InvalidEncoding.as_str(),
            "invalid-encoding"
        );
    }

    #[test]
    fn callback_query_accepts_ordering_unknown_fields_and_strict_encoding() {
        let query = parse_callback_query(&format!(
            "unknown=ignored&state={VALID_STATE}&scope=member&%63ode=a%2Bvalue"
        ))
        .unwrap();
        assert_eq!(query.state.as_str(), VALID_STATE);
        let ParsedAuthorization::Code(code) = query.authorization else {
            panic!("expected an authorization code");
        };
        assert_eq!(code.as_str(), "a+value");
        assert!(!format!("{code:?}").contains("a+value"));
        let encoded_state = format!("%41{}", &VALID_STATE[1..]);
        let encoded = parse_callback_query(&format!("code=ok&state={encoded_state}")).unwrap();
        assert_eq!(encoded.state.as_str(), VALID_STATE);

        let denied = parse_callback_query(&format!(
            "error_description=cancelled&state={VALID_STATE}&error=access_denied&error_uri=https%3A%2F%2Fprovider.invalid"
        ))
        .unwrap();
        assert!(matches!(denied.authorization, ParsedAuthorization::Denied));
        let failed = parse_callback_query(&format!(
            "error=temporarily_unavailable&state={VALID_STATE}"
        ))
        .unwrap();
        assert!(matches!(
            failed.authorization,
            ParsedAuthorization::ProviderFailed
        ));
    }

    #[test]
    fn callback_query_rejects_duplicates_conflicts_and_encoding_boundaries() {
        for query in [
            format!("code=one&code=two&state={VALID_STATE}"),
            format!("code=one&%63ode=two&state={VALID_STATE}"),
            format!("code=one&state={VALID_STATE}&state={VALID_STATE}"),
            format!("code=one&state={VALID_STATE}&%73tate={VALID_STATE}"),
            format!("error=access_denied&error=server_error&state={VALID_STATE}"),
            format!(
                "error=access_denied&error_description=a&error_description=b&state={VALID_STATE}"
            ),
            format!("error=access_denied&error_uri=a&error_uri=b&state={VALID_STATE}"),
        ] {
            assert!(matches!(
                parse_callback_query(&query),
                Err(CallbackQueryError::DuplicateParameter)
            ));
        }

        for query in [
            format!("code=one&error=access_denied&state={VALID_STATE}"),
            format!("code=one&error_description=unexpected&state={VALID_STATE}"),
            format!("error=&state={VALID_STATE}"),
            format!("state={VALID_STATE}"),
        ] {
            assert!(matches!(
                parse_callback_query(&query),
                Err(CallbackQueryError::InvalidOutcome)
            ));
        }
        assert!(matches!(
            parse_callback_query("code=one"),
            Err(CallbackQueryError::MissingState)
        ));
        assert!(matches!(
            parse_callback_query("code=one&state=short"),
            Err(CallbackQueryError::InvalidState)
        ));
        assert!(matches!(
            parse_callback_query(&format!("code=&state={VALID_STATE}")),
            Err(CallbackQueryError::InvalidCode)
        ));
        for query in [
            format!("code=one%&state={VALID_STATE}"),
            format!("code=one%2&state={VALID_STATE}"),
            format!("code=one%GG&state={VALID_STATE}"),
        ] {
            assert!(matches!(
                parse_callback_query(&query),
                Err(CallbackQueryError::InvalidEncoding)
            ));
        }
    }

    #[tokio::test]
    async fn tls_preflight_accepts_exact_pem_and_der_boundaries() {
        let listen = "127.0.0.1:0".parse().unwrap();
        let der = CallbackServer::from_config(&config_with(
            listen,
            vec![TEST_CERT_DER.to_vec()],
            TEST_KEY_DER.to_vec(),
        ))
        .await
        .unwrap();
        assert_eq!(der.listen(), listen);
        assert!(format!("{der:?}").contains("127.0.0.1:0"));

        let pem_server = CallbackServer::from_config(&config_with(
            listen,
            vec![pem("CERTIFICATE", TEST_CERT_DER)],
            pem("PRIVATE KEY", TEST_KEY_DER),
        ))
        .await
        .unwrap();
        assert_eq!(pem_server.listen(), listen);

        let der_chain = config_with(
            listen,
            vec![TEST_CERT_DER.to_vec(), TEST_CA_DER.to_vec()],
            TEST_KEY_DER.to_vec(),
        );
        assert!(CallbackServer::preflight(&der_chain).is_ok());
        let mut pem_chain = pem("CERTIFICATE", TEST_CERT_DER);
        pem_chain.extend_from_slice(&pem("CERTIFICATE", TEST_CA_DER));
        let pem_bundle = config_with(listen, vec![pem_chain], pem("PRIVATE KEY", TEST_KEY_DER));
        assert!(CallbackServer::preflight(&pem_bundle).is_ok());

        let invalid = config_with(
            listen,
            vec![b"not-a-certificate".to_vec()],
            TEST_KEY_DER.to_vec(),
        );
        assert!(matches!(
            CallbackServer::from_config(&invalid).await,
            Err(CallbackServerError::InvalidTlsCertificate(_))
        ));
        let mixed = config_with(
            listen,
            vec![pem("CERTIFICATE", TEST_CERT_DER)],
            TEST_KEY_DER.to_vec(),
        );
        assert!(matches!(
            CallbackServer::from_config(&mixed).await,
            Err(CallbackServerError::MixedTlsEncoding)
        ));
        let reverse_mixed = config_with(
            listen,
            vec![TEST_CERT_DER.to_vec()],
            pem("PRIVATE KEY", TEST_KEY_DER),
        );
        assert!(matches!(
            CallbackServer::preflight(&reverse_mixed),
            Err(CallbackServerError::MixedTlsEncoding)
        ));

        let malformed_certificate = config_with(
            listen,
            vec![b"-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n".to_vec()],
            pem("PRIVATE KEY", TEST_KEY_DER),
        );
        assert!(matches!(
            CallbackServer::preflight(&malformed_certificate),
            Err(CallbackServerError::InvalidTlsCertificatePem)
        ));
        let malformed_key = config_with(
            listen,
            vec![pem("CERTIFICATE", TEST_CERT_DER)],
            pem("CERTIFICATE", TEST_KEY_DER),
        );
        assert!(matches!(
            CallbackServer::preflight(&malformed_key),
            Err(CallbackServerError::InvalidTlsPrivateKeyPem)
        ));
        let mut duplicate_keys = pem("PRIVATE KEY", TEST_KEY_DER);
        duplicate_keys.extend_from_slice(&pem("PRIVATE KEY", TEST_KEY_DER));
        let duplicate_key = config_with(
            listen,
            vec![pem("CERTIFICATE", TEST_CERT_DER)],
            duplicate_keys,
        );
        assert!(matches!(
            CallbackServer::preflight(&duplicate_key),
            Err(CallbackServerError::InvalidTlsPrivateKeyPem)
        ));

        let non_certificate = pem("PRIVATE KEY", TEST_KEY_DER);
        assert!(matches!(
            parse_pem_certificates(&[non_certificate.as_slice()]),
            Err(CallbackServerError::InvalidTlsCertificatePem)
        ));
        assert!(matches!(
            parse_pem_certificates(&[b"not a PEM document"]),
            Err(CallbackServerError::InvalidTlsCertificatePem)
        ));

        let invalid_key_material = config_with(
            listen,
            vec![pem("CERTIFICATE", TEST_CERT_DER)],
            pem("PRIVATE KEY", b"invalid key material"),
        );
        let invalid_key_result = CallbackServer::preflight(&invalid_key_material);
        assert!(
            matches!(
                &invalid_key_result,
                Err(CallbackServerError::InvalidTlsPrivateKey)
            ),
            "unexpected invalid-key result: {invalid_key_result:?}"
        );

        // Syntactically valid PKCS#8 carrying the X25519 key-agreement OID:
        // rustls can classify the container, but cannot use it as a server
        // signing key and must fail before the listener is bound.
        let mut unsupported_signing_key = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
            0x04, 0x20,
        ];
        unsupported_signing_key.extend_from_slice(&[0x42; 32]);
        let unsupported_key = config_with(
            listen,
            vec![TEST_CERT_DER.to_vec()],
            unsupported_signing_key,
        );
        assert!(matches!(
            CallbackServer::preflight(&unsupported_key),
            Err(CallbackServerError::InvalidTlsPrivateKeyMaterial(_))
        ));
    }

    #[test]
    fn tls_preflight_rejects_mismatched_key_and_wrong_san() {
        let listen = "127.0.0.1:0".parse().unwrap();
        let mismatched = config_with(
            listen,
            vec![TEST_CERT_DER.to_vec()],
            TEST_MISMATCHED_KEY_DER.to_vec(),
        );
        assert!(matches!(
            CallbackServer::preflight(&mismatched),
            Err(CallbackServerError::TlsKeyMismatch)
        ));

        let wrong_name = config_with_url(
            listen,
            "https://relay.example.test",
            vec![TEST_CERT_DER.to_vec()],
            TEST_KEY_DER.to_vec(),
        );
        assert!(matches!(
            CallbackServer::preflight(&wrong_name),
            Err(CallbackServerError::CallbackCertificateName(_))
        ));
    }

    #[test]
    fn tls_preflight_matches_dns_and_ip_callback_hosts_to_leaf_san() {
        let listen = "127.0.0.1:0".parse().unwrap();
        for callback_url in ["https://localhost.", "https://127.0.0.1"] {
            let config = config_with_url(
                listen,
                callback_url,
                vec![TEST_CERT_DER.to_vec()],
                TEST_KEY_DER.to_vec(),
            );
            assert!(CallbackServer::preflight(&config).is_ok(), "{callback_url}");
        }

        let ipv6 = config_with_url(
            listen,
            "https://[::1]",
            vec![TEST_CERT_DER.to_vec()],
            TEST_KEY_DER.to_vec(),
        );
        assert!(matches!(
            CallbackServer::preflight(&ipv6),
            Err(CallbackServerError::CallbackCertificateName(_))
        ));
    }

    #[tokio::test]
    async fn bind_reports_an_occupied_callback_address() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap();
        let server = server_with(address).await;
        assert!(matches!(
            server.bind().await,
            Err(CallbackServerError::Bind {
                address: failed,
                ..
            }) if failed == address
        ));
    }

    #[tokio::test]
    async fn real_https_callback_routes_validate_inputs_and_are_not_cached() {
        let server = server_with("127.0.0.1:0".parse().unwrap()).await;
        let (listener, bound) = server.bind().await.unwrap();
        assert!(format!("{listener:?}").contains("LimitedListener"));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(
            server.serve_on(listener, Arc::new(RoutingHandler), async move {
                let _ = shutdown_rx.await;
            }),
        );
        let certificate = reqwest::Certificate::from_der(TEST_CA_DER).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(certificate)
            .https_only(true)
            .build()
            .unwrap();
        let base = format!("https://localhost:{}", bound.port());
        for (provider, code, status) in [
            ("wecom", "admitted", reqwest::StatusCode::OK),
            ("feishu", "rejected", reqwest::StatusCode::OK),
            ("wecom", "invalid-state", reqwest::StatusCode::BAD_REQUEST),
            (
                "wecom",
                "platform",
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
            ),
            ("wecom", "limited", reqwest::StatusCode::TOO_MANY_REQUESTS),
        ] {
            let response = client
                .get(format!(
                    "{base}/yonder/callback/{provider}?code={code}&state={VALID_STATE}"
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(
                response.headers()["content-security-policy"],
                "default-src 'none'"
            );
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(response.text().await.unwrap().contains("Yonder"));
        }

        let denied = client
            .get(format!(
                "{base}/yonder/callback/wecom?error_description=user%20cancelled&state={VALID_STATE}&error=access_denied"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), reqwest::StatusCode::OK);
        let denied_body = denied.text().await.unwrap();
        assert!(denied_body.contains("认证未通过"));
        assert!(!denied_body.contains("user cancelled"));

        let provider_failed = client
            .get(format!(
                "{base}/yonder/callback/feishu?state={VALID_STATE}&error=temporarily_unavailable"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            provider_failed.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            !provider_failed
                .text()
                .await
                .unwrap()
                .contains("temporarily")
        );

        let bad_paths = [
            "/yonder/callback/wecom",
            "/yonder/callback/wecom?state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/yonder/callback/wecom?code=admitted",
            "/yonder/callback/wecom?code=&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/yonder/callback/wecom?code=admitted&state=",
            "/yonder/callback/wecom?code=admitted&code=rejected&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/yonder/callback/wecom?code=admitted&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/yonder/callback/wecom?error=access_denied&error=server_error&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/yonder/callback/wecom?error=access_denied&error_description=a&error_description=b&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ];
        for path in bad_paths {
            assert_eq!(
                client
                    .get(format!("{base}{path}"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::BAD_REQUEST
            );
        }
        let oversized_query = "q".repeat(MAX_CALLBACK_QUERY_BYTES + 1);
        let oversized_code = "c".repeat(crate::verifier::MAX_AUTHORIZATION_CODE_BYTES + 1);
        let oversized_state = "s".repeat(MAX_CALLBACK_STATE_BYTES + 1);
        for path in [
            format!("/yonder/callback/wecom?{oversized_query}"),
            format!("/yonder/callback/wecom?code={oversized_code}&state={VALID_STATE}"),
            format!("/yonder/callback/wecom?code=admitted&state={oversized_state}"),
        ] {
            assert_eq!(
                client
                    .get(format!("{base}{path}"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            client
                .post(format!("{base}/yonder/callback/wecom"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            client
                .get(format!("{base}/unknown"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NOT_FOUND
        );
        let _ = shutdown_tx.send(());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn limited_listener_carries_capacity_addresses_io_and_deadlines() {
        let listener = LimitedListener::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = listener.get_local_addr().unwrap();
        assert!(format!("{address:?}").contains(&address.socket.to_string()));
        let source = CallbackSource::connect_info(address.clone());
        assert_eq!(source.ip, address.socket.ip());
        assert_eq!(source.deadline, address.deadline);

        let rebound = LimitedListener::bind_to(LimitedAddress {
            socket: "127.0.0.1:0".parse().unwrap(),
            permits: Arc::new(Semaphore::new(1)),
            deadline: tokio::time::Instant::now() + CALLBACK_CONNECTION_TIMEOUT,
        })
        .await
        .unwrap();
        assert_ne!(rebound.get_local_addr().unwrap().socket.port(), 0);

        let mut client = TcpStream::connect(address.socket).await.unwrap();
        let (mut server, remote) = listener.accept_stream().await.unwrap();
        assert_eq!(remote.socket.ip(), client.local_addr().unwrap().ip());
        assert_eq!(
            CallbackSource::connect_info(remote.clone()).deadline,
            remote.deadline
        );
        client.write_all(b"request").await.unwrap();
        let mut request = [0_u8; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        server.write_all(b"reply").await.unwrap();
        server.flush().await.unwrap();
        let mut reply = [0_u8; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        server.deadline = Box::pin(tokio::time::sleep(Duration::ZERO));
        server.deadline.as_mut().await;
        let mut byte = [0_u8; 1];
        assert_eq!(
            server.read(&mut byte).await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        server.deadline = Box::pin(tokio::time::sleep(Duration::ZERO));
        server.deadline.as_mut().await;
        assert_eq!(
            server.write(b"x").await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        server.deadline = Box::pin(tokio::time::sleep(Duration::ZERO));
        server.deadline.as_mut().await;
        assert_eq!(
            server.flush().await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            server.shutdown().await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );

        listener.permits.close();
        let error = listener.accept_stream().await.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn callback_handler_uses_the_connection_absolute_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        let source = CallbackSource {
            ip: "203.0.113.9".parse().unwrap(),
            deadline,
        };
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            dispatch(
                EnterpriseProvider::WeCom,
                State(CallbackState {
                    handler: Arc::new(PendingHandler),
                }),
                ConnectInfo(source),
                RawQuery(Some(format!("code=valid&state={VALID_STATE}"))),
            ),
        )
        .await
        .expect("the absolute callback deadline must cancel a slow handler");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(tokio::time::Instant::now() >= deadline);
    }
}
