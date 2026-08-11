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
use yonder_core::EnterpriseProvider;
use yonder_net::contains_pem_marker;

pub const MAX_CALLBACK_QUERY_BYTES: usize = 1024;
pub const MAX_CALLBACK_STATE_BYTES: usize = 128;
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

pub trait CallbackHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        provider: EnterpriseProvider,
        code: &'a str,
        state: &'a str,
        source: IpAddr,
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
    pub async fn from_config(config: &EnterpriseAuthConfig) -> Result<Self, CallbackServerError> {
        let certificate_documents: Vec<Vec<u8>> = config
            .certificate_chain()
            .iter()
            .map(|document| document.as_bytes().to_vec())
            .collect();
        let private_key = config.private_key().as_bytes().to_vec();
        let certificates_are_pem = certificate_documents
            .iter()
            .all(|document| contains_pem_marker(document));
        let certificates_are_der = certificate_documents
            .iter()
            .all(|document| !contains_pem_marker(document));
        let key_is_pem = contains_pem_marker(&private_key);

        let tls = if certificates_are_pem && key_is_pem {
            let mut chain = Vec::new();
            for document in certificate_documents {
                chain.extend_from_slice(&document);
                if !chain.ends_with(b"\n") {
                    chain.push(b'\n');
                }
            }
            RustlsConfig::from_pem(chain, private_key).await
        } else if certificates_are_der && !key_is_pem {
            RustlsConfig::from_der(certificate_documents, private_key).await
        } else {
            return Err(CallbackServerError::InvalidTlsMaterial);
        }
        .map_err(|_| CallbackServerError::InvalidTlsMaterial)?;

        Ok(Self {
            tls,
            listen: config.listen(),
        })
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

#[derive(Clone)]
struct CallbackState {
    handler: Arc<dyn CallbackHandler>,
}

#[derive(Debug, Clone, Copy)]
struct CallbackSource(IpAddr);

impl Connected<LimitedAddress> for CallbackSource {
    fn connect_info(address: LimitedAddress) -> Self {
        Self(address.socket.ip())
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
    let Some(query) = query else {
        log_rejected(provider, "missing-query");
        return response::bad_request();
    };
    if query.len() > MAX_CALLBACK_QUERY_BYTES {
        log_rejected(provider, "oversized-query");
        return response::bad_request();
    }
    let Some(code) = query_param(&query, "code") else {
        log_rejected(provider, "missing-code");
        return response::bad_request();
    };
    let Some(callback_state) = query_param(&query, "state") else {
        log_rejected(provider, "missing-state");
        return response::bad_request();
    };
    if code.is_empty()
        || code.len() > MAX_AUTHORIZATION_CODE_BYTES
        || callback_state.is_empty()
        || callback_state.len() > MAX_CALLBACK_STATE_BYTES
    {
        log_rejected(provider, "oversized-parameter");
        return response::bad_request();
    }

    response::result(
        state
            .handler
            .handle(provider, &code, &callback_state, source.0)
            .await,
    )
}

fn query_param(query: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
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
        let address = LimitedAddress {
            socket,
            permits: Arc::clone(&self.permits),
        };
        Ok((LimitedStream::new(stream, permit), address))
    }

    fn get_local_addr(&self) -> io::Result<LimitedAddress> {
        Ok(LimitedAddress {
            socket: self.inner.local_addr()?,
            permits: Arc::clone(&self.permits),
        })
    }
}

struct LimitedStream {
    inner: TcpStream,
    deadline: Pin<Box<tokio::time::Sleep>>,
    _permit: OwnedSemaphorePermit,
}

impl LimitedStream {
    fn new(inner: TcpStream, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep(CALLBACK_CONNECTION_TIMEOUT)),
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
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Debug, Error)]
pub enum CallbackServerError {
    #[error("the enterprise callback TLS material is invalid")]
    InvalidTlsMaterial,
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
        CALLBACK_CONNECTION_TIMEOUT, CallbackHandler, CallbackResult, CallbackServer,
        CallbackServerError, CallbackSource, LimitedAddress, LimitedListener,
        MAX_CALLBACK_CONNECTIONS, MAX_CALLBACK_QUERY_BYTES, MAX_CALLBACK_STATE_BYTES, query_param,
    };
    use crate::enterprise::{CallbackExternalUrl, EnterpriseAuthConfig, ProviderSecrets};
    use axum::extract::connect_info::Connected as _;
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
    const TEST_CA_DER: &[u8] = include_bytes!("../../yon/tests/fixtures/localhost-test-ca.der");

    struct RoutingHandler;

    impl CallbackHandler for RoutingHandler {
        fn handle<'a>(
            &'a self,
            _provider: EnterpriseProvider,
            code: &'a str,
            _state: &'a str,
            _source: std::net::IpAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CallbackResult> + Send + 'a>>
        {
            let result = match code {
                "admitted" => CallbackResult::Admitted,
                "rejected" => CallbackResult::Rejected,
                "invalid-state" => CallbackResult::InvalidState,
                "platform" => CallbackResult::Platform,
                "limited" => CallbackResult::Limited,
                _ => CallbackResult::Rejected,
            };
            Box::pin(std::future::ready(result))
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
        let providers = EnterpriseProviders::new(true, false).unwrap();
        let secrets = ProviderSecrets::new(
            providers,
            Some(std::path::PathBuf::from("wecom.secret")),
            None,
        )
        .unwrap();
        EnterpriseAuthConfig::new(
            listen,
            CallbackExternalUrl::new(Url::parse("https://relay.example.test").unwrap()).unwrap(),
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
        assert_eq!(MAX_CALLBACK_STATE_BYTES, 128);
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
        assert_eq!(
            query_param("code=a+value&state=b", "code").as_deref(),
            Some("a value")
        );
        assert_eq!(
            query_param("code=first&code=second", "code").as_deref(),
            Some("first")
        );
        assert_eq!(query_param("state=b", "code"), None);
    }

    #[tokio::test]
    async fn tls_documents_accept_consistent_pem_or_der_and_reject_other_material() {
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

        let invalid = config_with(
            listen,
            vec![b"not-a-certificate".to_vec()],
            TEST_KEY_DER.to_vec(),
        );
        assert!(matches!(
            CallbackServer::from_config(&invalid).await,
            Err(CallbackServerError::InvalidTlsMaterial)
        ));
        let mixed = config_with(
            listen,
            vec![pem("CERTIFICATE", TEST_CERT_DER)],
            TEST_KEY_DER.to_vec(),
        );
        assert!(matches!(
            CallbackServer::from_config(&mixed).await,
            Err(CallbackServerError::InvalidTlsMaterial)
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
                    "{base}/yonder/callback/{provider}?code={code}&state=state"
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

        let bad_paths = [
            "/yonder/callback/wecom",
            "/yonder/callback/wecom?state=state",
            "/yonder/callback/wecom?code=admitted",
            "/yonder/callback/wecom?code=&state=state",
            "/yonder/callback/wecom?code=admitted&state=",
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
            format!("/yonder/callback/wecom?code={oversized_code}&state=state"),
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
        assert_eq!(
            CallbackSource::connect_info(address.clone()).0,
            address.socket.ip()
        );

        let rebound = LimitedListener::bind_to(LimitedAddress {
            socket: "127.0.0.1:0".parse().unwrap(),
            permits: Arc::new(Semaphore::new(1)),
        })
        .await
        .unwrap();
        assert_ne!(rebound.get_local_addr().unwrap().socket.port(), 0);

        let mut client = TcpStream::connect(address.socket).await.unwrap();
        let (mut server, remote) = listener.accept_stream().await.unwrap();
        assert_eq!(remote.socket.ip(), client.local_addr().unwrap().ip());
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
        server.shutdown().await.unwrap();

        listener.permits.close();
        let error = listener.accept_stream().await.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }
}
