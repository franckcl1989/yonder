//! Bounded Reqwest transport for enterprise provider exchanges.

use crate::verifier::{ExchangeTransport, MAX_EXCHANGE_RESPONSE_BYTES};
use reqwest::header::CONTENT_TYPE;
use std::future::Future;
use std::io;
use std::time::Duration;
use url::Url;

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
        reqwest::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map(|client| Self { client })
            .map_err(map_reqwest_error)
    }

    async fn execute(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>, io::Error> {
        let mut response = request.send().await.map_err(map_reqwest_error)?;
        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "provider returned HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_EXCHANGE_RESPONSE_BYTES)
        {
            return Err(response_too_large());
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or_default()
                .min(MAX_EXCHANGE_RESPONSE_BYTES) as usize,
        );
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
            if chunk.len() > MAX_EXCHANGE_RESPONSE_BYTES as usize - body.len() {
                return Err(response_too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
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
        async move { self.execute(request).await }
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
        async move { self.execute(request).await }
    }
}

fn response_too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "provider response exceeded the configured bound",
    )
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
    use super::{EXCHANGE_REQUEST_TIMEOUT, ExchangeClient};
    use crate::verifier::{ExchangeTransport as _, MAX_EXCHANGE_RESPONSE_BYTES};
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::{Request, State};
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::Response;
    use axum::routing::any;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
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
        assert!(client.get(&status, None).await.is_err());
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
