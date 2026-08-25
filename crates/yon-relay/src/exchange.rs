//! Bounded Reqwest transport for enterprise provider exchanges.

use crate::verifier::{
    ExchangeError, ExchangeResponse, ExchangeTransport, MAX_EXCHANGE_RESPONSE_BYTES,
};
use reqwest::header::CONTENT_TYPE;
use std::future::Future;
use std::io;
use std::time::Duration;
use url::Url;
use zeroize::Zeroize;

/// Absolute deadline for one provider request, including its response body.
pub const EXCHANGE_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Shared high-level HTTP client for WeCom and Feishu exchanges.
#[derive(Debug, Clone)]
pub struct ExchangeClient {
    client: reqwest::Client,
}

impl ExchangeClient {
    /// Builds the production HTTPS-only client.
    pub fn new() -> Result<Self, io::Error> {
        Self::build(true, EXCHANGE_REQUEST_TIMEOUT)
    }

    #[cfg(test)]
    fn for_tests(timeout: Duration) -> Result<Self, io::Error> {
        Self::build(false, timeout)
    }

    fn build(https_only: bool, timeout: Duration) -> Result<Self, io::Error> {
        install_ring_crypto_provider()?;
        reqwest::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map(|client| Self { client })
            .map_err(map_reqwest_error)
    }

    async fn execute(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<ExchangeResponse, ExchangeError> {
        let mut response = request
            .send()
            .await
            .map_err(map_reqwest_error)
            .map_err(ExchangeError::from_io)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_EXCHANGE_RESPONSE_BYTES)
        {
            return Err(ExchangeError::ResponseTooLarge);
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or_default()
                .min(MAX_EXCHANGE_RESPONSE_BYTES) as usize,
        );
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(error) => {
                    body.zeroize();
                    return Err(ExchangeError::from_io(map_reqwest_error(error)));
                }
            };
            if chunk.len() > MAX_EXCHANGE_RESPONSE_BYTES as usize - body.len() {
                body.zeroize();
                return Err(ExchangeError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ExchangeResponse::new(status, body))
    }
}

/// Installs the process-wide Rustls provider selected for every relay TLS role.
///
/// Rustls permits one installation per process. Rechecking after a failed
/// install makes concurrent and repeated callers idempotent while still
/// failing closed if no provider became visible.
pub(crate) fn install_ring_crypto_provider() -> Result<(), io::Error> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        Ok(())
    } else {
        Err(io::Error::other(
            "the rustls ring crypto provider could not be installed",
        ))
    }
}

impl ExchangeTransport for ExchangeClient {
    fn get(
        &self,
        url: &Url,
        bearer: Option<&str>,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send {
        let mut request = self.client.get(url.clone());
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        async move {
            self.execute(request)
                .await
                .map_err(ExchangeError::into_io)?
                .into_success_body()
        }
    }

    fn post_json(
        &self,
        url: &Url,
        body: &str,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send {
        let request = self
            .client
            .post(url.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_owned());
        async move {
            self.execute(request)
                .await
                .map_err(ExchangeError::into_io)?
                .into_success_body()
        }
    }

    fn get_response<'a>(
        &'a self,
        url: &'a Url,
        bearer: Option<&'a str>,
    ) -> impl Future<Output = Result<ExchangeResponse, ExchangeError>> + Send + 'a {
        let mut request = self.client.get(url.clone());
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        async move { self.execute(request).await }
    }

    fn post_json_response<'a>(
        &'a self,
        url: &'a Url,
        body: &'a str,
    ) -> impl Future<Output = Result<ExchangeResponse, ExchangeError>> + Send + 'a {
        let request = self
            .client
            .post(url.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body.as_bytes().to_vec());
        async move { self.execute(request).await }
    }
}

fn map_reqwest_error(error: reqwest::Error) -> io::Error {
    let kind = if error.is_timeout() {
        io::ErrorKind::TimedOut
    } else if error.is_decode() || error.is_body() {
        io::ErrorKind::InvalidData
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{EXCHANGE_REQUEST_TIMEOUT, ExchangeClient, install_ring_crypto_provider};
    use crate::verifier::{ExchangeError, ExchangeTransport as _, MAX_EXCHANGE_RESPONSE_BYTES};
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::{Request, State};
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::Response;
    use axum::routing::any;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use url::Url;

    type CapturedRequest = (Method, Uri, HeaderMap, Vec<u8>);

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<CapturedRequest>>>);

    async fn capture_request(State(capture): State<Capture>, request: Request) -> Response<Body> {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 64 * 1024).await.unwrap().to_vec();
        *capture.0.lock().unwrap() = Some((parts.method, parts.uri, parts.headers, bytes));
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("provider-response"))
            .unwrap()
    }

    async fn server() -> (Url, Capture) {
        let capture = Capture::default();
        let app = Router::new()
            .fallback(any(capture_request))
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            Url::parse(&format!("http://{address}/exchange?q=1")).unwrap(),
            capture,
        )
    }

    async fn raw_server(response: Vec<u8>) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            let _ = socket.write_all(&response).await;
        });
        (
            Url::parse(&format!("http://{address}/exchange")).unwrap(),
            server,
        )
    }

    #[test]
    fn ring_provider_installation_is_repeated_and_concurrent_safe() {
        let barrier = Arc::new(std::sync::Barrier::new(17));
        let threads = (0..16)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    install_ring_crypto_provider()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        install_ring_crypto_provider().unwrap();
        install_ring_crypto_provider().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[tokio::test]
    async fn get_and_post_use_reqwest_and_preserve_required_fields() {
        let client = ExchangeClient::for_tests(EXCHANGE_REQUEST_TIMEOUT).unwrap();
        let (url, capture) = server().await;
        assert_eq!(
            client.get(&url, Some("secret-token")).await.unwrap(),
            b"provider-response"
        );
        let captured = capture.0.lock().unwrap().take().unwrap();
        assert_eq!(captured.0, Method::GET);
        assert_eq!(captured.1, "/exchange?q=1");
        assert_eq!(captured.2["authorization"], "Bearer secret-token");

        assert_eq!(
            client.post_json(&url, r#"{"value":1}"#).await.unwrap(),
            b"provider-response"
        );
        let captured = capture.0.lock().unwrap().take().unwrap();
        assert_eq!(captured.0, Method::POST);
        assert_eq!(captured.2["content-type"], "application/json");
        assert_eq!(captured.3, br#"{"value":1}"#);

        let response = client
            .get_response(&url, Some("response-token"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK.as_u16());
        assert_eq!(response.body(), b"provider-response");
        let captured = capture.0.lock().unwrap().take().unwrap();
        assert_eq!(captured.0, Method::GET);
        assert_eq!(captured.2["authorization"], "Bearer response-token");

        let response = client
            .post_json_response(&url, r#"{"value":2}"#)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK.as_u16());
        assert_eq!(response.body(), b"provider-response");
        let captured = capture.0.lock().unwrap().take().unwrap();
        assert_eq!(captured.0, Method::POST);
        assert_eq!(captured.2["content-type"], "application/json");
        assert_eq!(captured.3, br#"{"value":2}"#);
    }

    #[tokio::test]
    async fn streaming_failures_and_unknown_lengths_fail_closed() {
        let client = ExchangeClient::for_tests(EXCHANGE_REQUEST_TIMEOUT).unwrap();
        let (url, server) = raw_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nabc"
                .to_vec(),
        )
        .await;
        assert_eq!(
            client.get(&url, None).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        server.await.unwrap();

        let oversized_len = MAX_EXCHANGE_RESPONSE_BYTES as usize + 1;
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{oversized_len:X}\r\n"
        )
        .into_bytes();
        response.resize(response.len() + oversized_len, b'x');
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (url, server) = raw_server(response).await;
        assert!(matches!(
            client.get_response(&url, None).await,
            Err(ExchangeError::ResponseTooLarge)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn non_success_and_oversized_responses_fail_closed() {
        async fn status() -> (StatusCode, &'static str) {
            (StatusCode::UNAUTHORIZED, "denied")
        }
        async fn oversized() -> Vec<u8> {
            vec![0_u8; MAX_EXCHANGE_RESPONSE_BYTES as usize + 1]
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/status", axum::routing::get(status))
            .route("/large", axum::routing::get(oversized));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = ExchangeClient::for_tests(EXCHANGE_REQUEST_TIMEOUT).unwrap();
        let status = Url::parse(&format!("http://{address}/status")).unwrap();
        let large = Url::parse(&format!("http://{address}/large")).unwrap();
        let preserved = client.get_response(&status, None).await.unwrap();
        assert_eq!(preserved.status(), StatusCode::UNAUTHORIZED.as_u16());
        assert_eq!(preserved.body(), b"denied");
        assert!(client.get(&status, None).await.is_err());
        assert!(matches!(
            client.get_response(&large, None).await,
            Err(ExchangeError::ResponseTooLarge)
        ));
        assert_eq!(
            client.get(&large, None).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn production_client_rejects_plain_http_and_deadlines_apply() {
        let production = ExchangeClient::new().unwrap();
        let url = Url::parse("http://127.0.0.1:1/").unwrap();
        assert!(production.get(&url, None).await.is_err());

        async fn delayed() -> &'static str {
            tokio::time::sleep(Duration::from_millis(100)).await;
            "late"
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/", axum::routing::get(delayed));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = ExchangeClient::for_tests(Duration::from_millis(20)).unwrap();
        let url = Url::parse(&format!("http://{address}/")).unwrap();
        assert_eq!(
            client.get(&url, None).await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
