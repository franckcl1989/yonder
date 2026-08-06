//! The production hyper transport for enterprise member verification.
//!
//! Implements `ExchangeTransport` with the committed single HTTP stack:
//! hyper 1.x client over rustls (webpki roots) for the WeCom and Feishu
//! OAuth exchanges. Every exchange request is bounded in time and the
//! response body is capped at `MAX_EXCHANGE_RESPONSE_BYTES`; oversized
//! bodies, non-success statuses and timeouts all fail the exchange.

use crate::verifier::{ExchangeTransport, MAX_EXCHANGE_RESPONSE_BYTES};
use http_body_util::BodyExt as _;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::future::Future;
use std::io;
use std::time::Duration;
use url::Url;

/// Bound on one provider exchange request.
pub const EXCHANGE_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A bounded hyper exchange client, safe to share across sessions.
#[derive(Debug, Clone)]
pub struct ExchangeClient {
    client: Client<HttpsConnector<HttpConnector>, String>,
}

impl ExchangeClient {
    /// Builds the client over the webpki root store. Construction cannot
    /// fail: the webpki root bundle is static and always installable.
    #[must_use]
    pub fn new() -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        }
    }
}

impl Default for ExchangeClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ExchangeTransport for ExchangeClient {
    fn get(
        &self,
        url: &Url,
        bearer: Option<&str>,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send {
        let client = self.client.clone();
        let uri = url.to_string();
        let authorization = bearer.map(str::to_owned);
        async move {
            let request = build_get_request(uri, authorization.as_deref())?;
            exchange(&client, request).await
        }
    }

    fn post_json(
        &self,
        url: &Url,
        body: &str,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send {
        let client = self.client.clone();
        let uri = url.to_string();
        let body = body.to_owned();
        async move {
            let request = build_post_request(uri, body)?;
            exchange(&client, request).await
        }
    }
}

fn build_get_request(
    uri: String,
    authorization: Option<&str>,
) -> Result<hyper::Request<String>, io::Error> {
    let mut builder = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri);
    if let Some(token) = authorization {
        builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .body(String::new())
        .map_err(|error| io::Error::other(format!("invalid exchange request: {error}")))
}

fn build_post_request(
    uri: String,
    body: String,
) -> Result<hyper::Request<String>, io::Error> {
    hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| io::Error::other(format!("invalid exchange request: {error}")))
}

async fn exchange(
    client: &Client<HttpsConnector<HttpConnector>, String>,
    request: hyper::Request<String>,
) -> Result<Vec<u8>, io::Error> {
    let response = tokio::time::timeout(EXCHANGE_REQUEST_TIMEOUT, client.request(request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "exchange request timed out"))?
        .map_err(|error| io::Error::other(format!("exchange request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "provider returned HTTP {}",
            response.status()
        )));
    }
    let body = response.into_body();
    let bytes =
        http_body_util::Limited::new(body, MAX_EXCHANGE_RESPONSE_BYTES as usize)
            .collect()
            .await
            .map_err(|error| {
                let kind = if error
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    io::ErrorKind::InvalidData
                } else {
                    io::ErrorKind::UnexpectedEof
                };
                io::Error::new(kind, format!("exchange response read failed: {error}"))
            })?
            .to_bytes();
    Ok(bytes.to_vec())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{ExchangeClient, build_get_request, build_post_request};
    use crate::verifier::ExchangeTransport as _;
    use http_body_util::BodyExt as _;
    use hyper::body::Incoming;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use url::Url;

    type Captured = Option<(String, String, String, String)>;

    /// Serves one HTTP/1 request on loopback and captures its line.
    async fn serve_one(response: hyper::Response<String>) -> (String, Arc<Mutex<Captured>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(None));
        let capture = captured.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                let capture = capture.clone();
                let response = response.clone();
                async move {
                    let method = request.method().to_string();
                    let uri = request.uri().to_string();
                    let authorization = request
                        .headers()
                        .get(hyper::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
                        .unwrap_or_default();
                    *capture.lock().unwrap() = Some((method, uri, authorization, body));
                    Ok::<_, Infallible>(response)
                }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(io, service)
            .await;
        });
        (address.to_string(), captured)
    }

    fn client() -> ExchangeClient {
        ExchangeClient::new()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_with_bearer_round_trips_over_http() {
        let (address, captured) = serve_one(
            hyper::Response::builder()
                .status(200)
                .body(r#"{"code":0}"#.to_owned())
                .unwrap(),
        )
        .await;
        let url = Url::parse(&format!("http://{address}/yonder/test")).unwrap();
        let body = client().get(&url, Some("tok-9")).await.unwrap();
        assert_eq!(body, br#"{"code":0}"#);
        let (method, uri, authorization, _) = captured.lock().unwrap().clone().unwrap();
        assert_eq!(method, "GET");
        assert_eq!(uri, "/yonder/test");
        assert_eq!(authorization, "Bearer tok-9");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_json_round_trips_over_http() {
        let (address, captured) = serve_one(
            hyper::Response::builder()
                .status(200)
                .body(r#"{"code":0}"#.to_owned())
                .unwrap(),
        )
        .await;
        let url = Url::parse(&format!("http://{address}/yonder/oidc")).unwrap();
        let body = client().post_json(&url, r#"{"grant_type":"authorization_code"}"#).await.unwrap();
        assert_eq!(body, br#"{"code":0}"#);
        let (method, uri, authorization, body) = captured.lock().unwrap().clone().unwrap();
        assert_eq!(method, "POST");
        assert_eq!(uri, "/yonder/oidc");
        assert!(authorization.is_empty());
        assert_eq!(body, r#"{"grant_type":"authorization_code"}"#);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_success_status_fails_the_exchange() {
        let (address, _) = serve_one(
            hyper::Response::builder()
                .status(500)
                .body("boom".to_owned())
                .unwrap(),
        )
        .await;
        let url = Url::parse(&format!("http://{address}/yonder/test")).unwrap();
        let error = client().get(&url, None).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(error.to_string().contains("HTTP 500"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_bodies_fail_the_exchange() {
        let big = "x".repeat((crate::verifier::MAX_EXCHANGE_RESPONSE_BYTES + 1) as usize);
        let (address, _) = serve_one(
            hyper::Response::builder()
                .status(200)
                .body(big)
                .unwrap(),
        )
        .await;
        let url = Url::parse(&format!("http://{address}/yonder/test")).unwrap();
        let error = client().get(&url, None).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn request_builders_set_method_uri_and_headers() {
        let get = build_get_request("https://relay.example.test/x".to_owned(), Some("tok-1"))
            .unwrap();
        assert_eq!(get.method(), hyper::Method::GET);
        assert_eq!(get.uri(), "https://relay.example.test/x");
        assert_eq!(
            get.headers()
                .get(hyper::header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer tok-1"
        );
        let bare = build_get_request("https://relay.example.test/x".to_owned(), None).unwrap();
        assert!(bare.headers().get(hyper::header::AUTHORIZATION).is_none());

        let post = build_post_request("https://relay.example.test/y".to_owned(), "{}".to_owned())
            .unwrap();
        assert_eq!(post.method(), hyper::Method::POST);
        assert_eq!(
            post.headers()
                .get(hyper::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json"
        );
        assert_eq!(post.body(), "{}");
    }
}
