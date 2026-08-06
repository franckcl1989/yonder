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
use crate::verifier::MAX_AUTHORIZATION_CODE_BYTES;
use hyper::body::Incoming;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use yonder_core::{EnterpriseProvider, SecretDocument};

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

/// Extracts one percent-decoded query parameter by name.
///
/// The url crate's form-urlencoded parser is lenient about malformed
/// percent escapes, which is safe here: the state parameter is still
/// strictly hex-decoded and the code is rejected by the provider
/// exchange, so malformed input fails closed either way.
fn query_param(query: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
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
        MAX_CALLBACK_QUERY_BYTES, query_param,
    };
    use crate::enterprise::{CallbackExternalUrl, EnterpriseAuthConfig, ProviderSecrets};
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
    fn query_params_decode_percent_and_plus_and_report_missing() {
        assert_eq!(query_param("code=a&state=b", "code"), Some("a".to_owned()));
        assert_eq!(query_param("code=a&state=b", "state"), Some("b".to_owned()));
        assert_eq!(query_param("state=b", "code"), None);
        assert_eq!(
            query_param("code=a%20b&state=c", "code"),
            Some("a b".to_owned())
        );
        assert_eq!(
            query_param("code=a+b&state=c", "code"),
            Some("a b".to_owned())
        );
        assert_eq!(
            query_param("code=a%2Fb&state=c", "code"),
            Some("a/b".to_owned())
        );
        // The parser is lenient about malformed escapes; the downstream
        // strict state hex-decoding and provider exchange reject them.
        assert_eq!(
            query_param("code=a%zz&state=b", "code"),
            Some("a%zz".to_owned())
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
