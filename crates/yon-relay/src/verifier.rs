//! Bounded enterprise member verification via current provider OAuth APIs.
//!
//! Provider adapters parse only typed, bounded response schemas. Application
//! tokens use one fixed cache entry per provider, monotonic early expiry and an
//! async mutex as a singleflight boundary. Provider and transport failures fail
//! closed and never place response bodies or secrets in diagnostics.

use crate::provider::{
    FeishuCredentials, MAX_PROVIDER_TOKEN_TTL, ProviderCredentials, ProviderField, SecretText,
    WeComCredentials,
};
use crate::session::MemberIdentity;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::io;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;
use yonder_core::EnterpriseProvider;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Bound on one provider API response body.
pub const MAX_EXCHANGE_RESPONSE_BYTES: u64 = 64 * 1024;
/// Bound on the OAuth authorization code.
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 512;

const WECOM_TOKEN_INVALID: [i64; 2] = [40_014, 42_001];
const WECOM_OAUTH_CODE_REJECTED: [i64; 3] = [40_029, 42_003, 42_022];
const WECOM_MEMBER_REJECTED: [i64; 2] = [60_021, 60_111];
const FEISHU_TENANT_TOKEN_INVALID: [i64; 2] = [99_991_663, 99_991_665];
const FEISHU_MEMBER_REJECTED: [i64; 5] = [20_008, 20_010, 20_021, 20_022, 20_023];

/// A bounded provider response that preserves HTTP status and body.
///
/// Debug deliberately omits the body because successful token responses and
/// error descriptions can contain credentials or authorization material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExchangeResponse {
    status: u16,
    body: Vec<u8>,
}

impl ExchangeResponse {
    /// Constructs a response returned by an exchange transport.
    #[must_use]
    pub const fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// Constructs a compatibility response for transports that only expose
    /// successful bodies.
    #[must_use]
    pub const fn success(body: Vec<u8>) -> Self {
        Self::new(200, body)
    }

    /// The HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Whether the HTTP status is in the success range.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The bounded response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn into_success_body(mut self) -> Result<Vec<u8>, io::Error> {
        if !self.is_success() {
            return Err(io::Error::other(format!(
                "provider returned HTTP {}",
                self.status
            )));
        }
        Ok(std::mem::take(&mut self.body))
    }
}

impl fmt::Debug for ExchangeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExchangeResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Structured transport failures before provider-specific response mapping.
#[derive(Error)]
pub enum ExchangeError {
    /// Network, TLS, timeout or response streaming failure.
    #[error("provider transport failed")]
    Transport(io::ErrorKind),
    /// The provider response exceeded the configured body bound.
    #[error("provider response exceeded the configured bound")]
    ResponseTooLarge,
}

impl fmt::Debug for ExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(kind) => formatter.debug_tuple("Transport").field(kind).finish(),
            Self::ResponseTooLarge => formatter.write_str("ResponseTooLarge"),
        }
    }
}

impl ExchangeError {
    pub(crate) fn from_io(error: io::Error) -> Self {
        Self::Transport(error.kind())
    }

    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Self::Transport(kind) => io::Error::new(kind, "provider transport failed"),
            Self::ResponseTooLarge => io::Error::new(
                io::ErrorKind::InvalidData,
                "provider response exceeded the configured bound",
            ),
        }
    }
}

/// Minimal outbound exchange transport, injectable for tests.
///
/// Existing test transports may implement only get and post_json. Production
/// transports override the response methods so non-2xx status and bounded body
/// remain available to the typed provider adapter.
pub trait ExchangeTransport {
    /// Executes a GET request with an optional bearer token.
    fn get(
        &self,
        url: &Url,
        bearer: Option<&str>,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send;

    /// Executes a JSON POST request.
    fn post_json(
        &self,
        url: &Url,
        body: &str,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send;

    /// Executes a GET while retaining its HTTP status.
    fn get_response<'a>(
        &'a self,
        url: &'a Url,
        bearer: Option<&'a str>,
    ) -> impl Future<Output = Result<ExchangeResponse, ExchangeError>> + Send + 'a
    where
        Self: Sync,
    {
        async move {
            self.get(url, bearer)
                .await
                .map(ExchangeResponse::success)
                .map_err(ExchangeError::from_io)
        }
    }

    /// Executes a JSON POST while retaining its HTTP status.
    fn post_json_response<'a>(
        &'a self,
        url: &'a Url,
        body: &'a str,
    ) -> impl Future<Output = Result<ExchangeResponse, ExchangeError>> + Send + 'a
    where
        Self: Sync,
    {
        async move {
            self.post_json(url, body)
                .await
                .map(ExchangeResponse::success)
                .map_err(ExchangeError::from_io)
        }
    }
}

/// Replaceable enterprise membership provider boundary.
///
/// Built-in adapters use static dispatch. Implementations own provider-specific
/// endpoint, schema, token and membership semantics without leaking them into
/// the callback/session state machine.
pub trait EnterpriseAuthProvider: Sync {
    /// Verifies one bounded authorization code and returns an active member.
    fn verify<'a, T>(
        &'a self,
        transport: &'a T,
        code: &'a str,
    ) -> impl Future<Output = Result<MemberIdentity, VerifyError>> + Send + 'a
    where
        T: ExchangeTransport + Sync + 'a;
}

struct WeComProvider<'a> {
    credentials: &'a ProviderCredentials,
}

impl EnterpriseAuthProvider for WeComProvider<'_> {
    async fn verify<'a, T>(
        &'a self,
        transport: &'a T,
        code: &'a str,
    ) -> Result<MemberIdentity, VerifyError>
    where
        T: ExchangeTransport + Sync + 'a,
    {
        verify_wecom(transport, self.credentials, code).await
    }
}

struct FeishuProvider<'a> {
    credentials: &'a ProviderCredentials,
}

impl EnterpriseAuthProvider for FeishuProvider<'_> {
    async fn verify<'a, T>(
        &'a self,
        transport: &'a T,
        code: &'a str,
    ) -> Result<MemberIdentity, VerifyError>
    where
        T: ExchangeTransport + Sync + 'a,
    {
        verify_feishu(transport, self.credentials, code).await
    }
}

/// Verifies the OAuth authorization code against the configured provider.
pub async fn verify_member<T: ExchangeTransport + Sync>(
    transport: &T,
    provider: EnterpriseProvider,
    code: &str,
    credentials: &ProviderCredentials,
) -> Result<MemberIdentity, VerifyError> {
    if code.is_empty() || code.len() > MAX_AUTHORIZATION_CODE_BYTES {
        return Err(VerifyError::InvalidCode);
    }
    match provider {
        EnterpriseProvider::WeCom => {
            if credentials.wecom().is_none() {
                return Err(VerifyError::Platform);
            }
            WeComProvider { credentials }.verify(transport, code).await
        }
        EnterpriseProvider::Feishu => {
            if credentials.feishu().is_none() {
                return Err(VerifyError::Platform);
            }
            FeishuProvider { credentials }.verify(transport, code).await
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderCallFailure {
    TokenInvalid,
    Rejected,
    Platform,
    ResponseTooLarge,
}

impl From<ProviderCallFailure> for VerifyError {
    fn from(failure: ProviderCallFailure) -> Self {
        match failure {
            ProviderCallFailure::Rejected => Self::Rejected,
            ProviderCallFailure::ResponseTooLarge => Self::ResponseTooLarge,
            ProviderCallFailure::TokenInvalid | ProviderCallFailure::Platform => Self::Platform,
        }
    }
}

fn map_exchange_error(error: ExchangeError) -> ProviderCallFailure {
    match error {
        ExchangeError::ResponseTooLarge => ProviderCallFailure::ResponseTooLarge,
        ExchangeError::Transport(_) => ProviderCallFailure::Platform,
    }
}

fn checked_response(response: ExchangeResponse) -> Result<ExchangeResponse, ProviderCallFailure> {
    if u64::try_from(response.body().len())
        .map_or(true, |length| length > MAX_EXCHANGE_RESPONSE_BYTES)
    {
        return Err(ProviderCallFailure::ResponseTooLarge);
    }
    Ok(response)
}

fn parse_response<T: serde::de::DeserializeOwned>(
    response: &ExchangeResponse,
) -> Result<T, ProviderCallFailure> {
    serde_json::from_slice(response.body()).map_err(|_| ProviderCallFailure::Platform)
}

fn token_lifetime(seconds: u64) -> Result<Duration, ProviderCallFailure> {
    let lifetime = Duration::from_secs(seconds);
    if lifetime.is_zero() || lifetime > MAX_PROVIDER_TOKEN_TTL {
        Err(ProviderCallFailure::Platform)
    } else {
        Ok(lifetime)
    }
}

fn provider_token(value: String) -> Result<SecretText, ProviderCallFailure> {
    SecretText::new(value, ProviderField::AccessToken).map_err(|_| ProviderCallFailure::Platform)
}

fn member_identity(user_id: &str) -> Result<MemberIdentity, VerifyError> {
    MemberIdentity::new(user_id.as_bytes()).map_err(|_| VerifyError::Platform)
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct WeComTokenResponse {
    errcode: i64,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct WeComUserInfoResponse {
    errcode: i64,
    #[serde(default)]
    userid: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct WeComMemberResponse {
    errcode: i64,
    #[serde(default)]
    status: Option<i64>,
}

async fn fetch_wecom_token<T: ExchangeTransport + Sync>(
    transport: &T,
    credentials: &WeComCredentials,
) -> Result<(SecretText, Duration), ProviderCallFailure> {
    let mut url =
        Url::parse("https://qyapi.weixin.qq.com/cgi-bin/gettoken").expect("fixed WeCom endpoint");
    url.query_pairs_mut()
        .append_pair("corpid", credentials.corp_id.as_str())
        .append_pair("corpsecret", credentials.app_secret.as_str());
    let response = checked_response(
        transport
            .get_response(&url, None)
            .await
            .map_err(map_exchange_error)?,
    )?;
    let success = response.is_success();
    let mut parsed: WeComTokenResponse = parse_response(&response)?;
    if !success || parsed.errcode != 0 {
        return Err(ProviderCallFailure::Platform);
    }
    let token = provider_token(std::mem::take(&mut parsed.access_token))?;
    let lifetime = token_lifetime(parsed.expires_in)?;
    Ok((token, lifetime))
}

async fn wecom_access_token<T: ExchangeTransport + Sync>(
    transport: &T,
    credentials: &ProviderCredentials,
    wecom: &WeComCredentials,
) -> Result<SecretText, ProviderCallFailure> {
    let mut cache = credentials.wecom_token_cache().await;
    let now = Instant::now();
    if let Some(token) = cache.fresh(now) {
        return Ok(token);
    }
    let (token, lifetime) = fetch_wecom_token(transport, wecom).await?;
    let stored_at = Instant::now();
    cache
        .store(token, lifetime, stored_at)
        .map_err(|()| ProviderCallFailure::Platform)?;
    cache.fresh(stored_at).ok_or(ProviderCallFailure::Platform)
}

async fn invalidate_wecom_token(credentials: &ProviderCredentials, failed: &SecretText) {
    credentials.wecom_token_cache().await.invalidate_if(failed);
}

async fn wecom_member_userid<T: ExchangeTransport + Sync>(
    transport: &T,
    token: &SecretText,
    code: &str,
) -> Result<Zeroizing<String>, ProviderCallFailure> {
    let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo")
        .expect("fixed WeCom endpoint");
    url.query_pairs_mut()
        .append_pair("access_token", token.as_str())
        .append_pair("code", code);
    let response = checked_response(
        transport
            .get_response(&url, None)
            .await
            .map_err(map_exchange_error)?,
    )?;
    let success = response.is_success();
    let mut parsed: WeComUserInfoResponse = parse_response(&response)?;
    if WECOM_TOKEN_INVALID.contains(&parsed.errcode) {
        return Err(ProviderCallFailure::TokenInvalid);
    }
    if WECOM_OAUTH_CODE_REJECTED.contains(&parsed.errcode)
        || WECOM_MEMBER_REJECTED.contains(&parsed.errcode)
    {
        return Err(ProviderCallFailure::Rejected);
    }
    if !success {
        return Err(ProviderCallFailure::Platform);
    }
    match parsed.errcode {
        0 => parsed
            .userid
            .take()
            .filter(|userid| !userid.is_empty())
            .map(Zeroizing::new)
            .ok_or(ProviderCallFailure::Rejected),
        _ => Err(ProviderCallFailure::Platform),
    }
}

async fn wecom_active_member_status<T: ExchangeTransport + Sync>(
    transport: &T,
    token: &SecretText,
    userid: &str,
) -> Result<(), ProviderCallFailure> {
    let mut url =
        Url::parse("https://qyapi.weixin.qq.com/cgi-bin/user/get").expect("fixed WeCom endpoint");
    url.query_pairs_mut()
        .append_pair("access_token", token.as_str())
        .append_pair("userid", userid);
    let response = checked_response(
        transport
            .get_response(&url, None)
            .await
            .map_err(map_exchange_error)?,
    )?;
    let success = response.is_success();
    let parsed: WeComMemberResponse = parse_response(&response)?;
    if WECOM_TOKEN_INVALID.contains(&parsed.errcode) {
        return Err(ProviderCallFailure::TokenInvalid);
    }
    if WECOM_MEMBER_REJECTED.contains(&parsed.errcode) {
        return Err(ProviderCallFailure::Rejected);
    }
    if !success {
        return Err(ProviderCallFailure::Platform);
    }
    match parsed.errcode {
        0 if parsed.status == Some(1) => Ok(()),
        0 => Err(ProviderCallFailure::Rejected),
        _ => Err(ProviderCallFailure::Platform),
    }
}

async fn verify_wecom<T: ExchangeTransport + Sync>(
    transport: &T,
    credentials: &ProviderCredentials,
    code: &str,
) -> Result<MemberIdentity, VerifyError> {
    let wecom = credentials.wecom().ok_or(VerifyError::Platform)?;
    let mut token = wecom_access_token(transport, credentials, wecom)
        .await
        .map_err(VerifyError::from)?;
    let mut refreshed = false;

    let userid = loop {
        match wecom_member_userid(transport, &token, code).await {
            Ok(userid) => break userid,
            Err(ProviderCallFailure::TokenInvalid) if !refreshed => {
                invalidate_wecom_token(credentials, &token).await;
                token = wecom_access_token(transport, credentials, wecom)
                    .await
                    .map_err(VerifyError::from)?;
                refreshed = true;
            }
            Err(error) => return Err(error.into()),
        }
    };

    loop {
        match wecom_active_member_status(transport, &token, &userid).await {
            Ok(()) => return member_identity(&userid),
            Err(ProviderCallFailure::TokenInvalid) if !refreshed => {
                invalidate_wecom_token(credentials, &token).await;
                token = wecom_access_token(transport, credentials, wecom)
                    .await
                    .map_err(VerifyError::from)?;
                refreshed = true;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[derive(Serialize)]
struct FeishuOAuthRequest<'a> {
    grant_type: &'static str,
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuOAuthResponse {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuUserInfoEnvelope {
    code: i64,
    #[serde(default)]
    data: Option<FeishuUserInfo>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuUserInfo {
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    tenant_key: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuTenantTokenResponse {
    code: i64,
    #[serde(default)]
    tenant_access_token: String,
    #[serde(default)]
    expire: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuMemberEnvelope {
    code: i64,
    #[serde(default)]
    data: Option<FeishuMemberData>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuMemberData {
    #[serde(default)]
    user: Option<FeishuMember>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuMember {
    #[serde(default)]
    status: Option<FeishuMemberStatus>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FeishuMemberStatus {
    #[serde(default)]
    is_activated: Option<bool>,
    #[serde(default)]
    is_frozen: Option<bool>,
    #[serde(default)]
    is_resigned: Option<bool>,
    #[serde(default)]
    is_exited: Option<bool>,
    #[serde(default)]
    is_unjoin: Option<bool>,
}

impl FeishuMemberStatus {
    const fn is_active(&self) -> bool {
        matches!(self.is_activated, Some(true))
            && matches!(self.is_frozen, Some(false))
            && matches!(self.is_resigned, Some(false))
            && matches!(self.is_exited, Some(false))
            && matches!(self.is_unjoin, Some(false))
    }
}

async fn feishu_user_token<T: ExchangeTransport + Sync>(
    transport: &T,
    credentials: &ProviderCredentials,
    feishu: &FeishuCredentials,
    code: &str,
) -> Result<SecretText, ProviderCallFailure> {
    let url =
        Url::parse("https://accounts.feishu.cn/oauth/v3/token").expect("fixed Feishu endpoint");
    let redirect_uri = credentials.feishu_redirect_uri();
    let body = Zeroizing::new(
        serde_json::to_string(&FeishuOAuthRequest {
            grant_type: "authorization_code",
            client_id: feishu.app_id.as_str(),
            client_secret: feishu.app_secret.as_str(),
            code,
            redirect_uri: redirect_uri.as_str(),
        })
        .map_err(|_| ProviderCallFailure::Platform)?,
    );
    let response = checked_response(
        transport
            .post_json_response(&url, &body)
            .await
            .map_err(map_exchange_error)?,
    )?;
    let success = response.is_success();
    let mut parsed: FeishuOAuthResponse = parse_response(&response)?;
    if !success {
        return if parsed.error.as_deref() == Some("invalid_grant") {
            Err(ProviderCallFailure::Rejected)
        } else {
            Err(ProviderCallFailure::Platform)
        };
    }
    if parsed.code.is_some_and(|code| code != 0) {
        return Err(ProviderCallFailure::Platform);
    }
    let token = provider_token(std::mem::take(&mut parsed.access_token))?;
    let _ = token_lifetime(parsed.expires_in)?;
    Ok(token)
}

async fn feishu_employee_id<T: ExchangeTransport + Sync>(
    transport: &T,
    credentials: &FeishuCredentials,
    user_token: &SecretText,
) -> Result<Zeroizing<String>, ProviderCallFailure> {
    let url = Url::parse("https://open.feishu.cn/open-apis/authen/v1/user_info")
        .expect("fixed Feishu endpoint");
    let response = checked_response(
        transport
            .get_response(&url, Some(user_token.as_str()))
            .await
            .map_err(map_exchange_error)?,
    )?;
    let success = response.is_success();
    let mut parsed: FeishuUserInfoEnvelope = parse_response(&response)?;
    if !success {
        return Err(ProviderCallFailure::Platform);
    }
    if parsed.code != 0 {
        return if parsed.code == 99_991_668 {
            Err(ProviderCallFailure::Rejected)
        } else {
            Err(ProviderCallFailure::Platform)
        };
    }
    let mut data = parsed.data.take().ok_or(ProviderCallFailure::Platform)?;
    if data.tenant_key != credentials.tenant_key.as_str() {
        return Err(ProviderCallFailure::Rejected);
    }
    let user_id = std::mem::take(&mut data.user_id);
    if user_id.is_empty() {
        Err(ProviderCallFailure::Rejected)
    } else {
        Ok(Zeroizing::new(user_id))
    }
}

async fn fetch_feishu_tenant_token<T: ExchangeTransport + Sync>(
    transport: &T,
    credentials: &FeishuCredentials,
) -> Result<(SecretText, Duration), ProviderCallFailure> {
    let url = Url::parse("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal")
        .expect("fixed Feishu endpoint");
    #[derive(Serialize)]
    struct Request<'a> {
        app_id: &'a str,
        app_secret: &'a str,
    }
    let body = Zeroizing::new(
        serde_json::to_string(&Request {
            app_id: credentials.app_id.as_str(),
            app_secret: credentials.app_secret.as_str(),
        })
        .map_err(|_| ProviderCallFailure::Platform)?,
    );
    let response = checked_response(
        transport
            .post_json_response(&url, &body)
            .await
            .map_err(map_exchange_error)?,
    )?;
    let success = response.is_success();
    let mut parsed: FeishuTenantTokenResponse = parse_response(&response)?;
    if !success || parsed.code != 0 {
        return Err(ProviderCallFailure::Platform);
    }
    let token = provider_token(std::mem::take(&mut parsed.tenant_access_token))?;
    let lifetime = token_lifetime(parsed.expire)?;
    Ok((token, lifetime))
}

async fn feishu_tenant_access_token<T: ExchangeTransport + Sync>(
    transport: &T,
    all_credentials: &ProviderCredentials,
    credentials: &FeishuCredentials,
) -> Result<SecretText, ProviderCallFailure> {
    let mut cache = all_credentials.feishu_tenant_token_cache().await;
    let now = Instant::now();
    if let Some(token) = cache.fresh(now) {
        return Ok(token);
    }
    let (token, lifetime) = fetch_feishu_tenant_token(transport, credentials).await?;
    let stored_at = Instant::now();
    cache
        .store(token, lifetime, stored_at)
        .map_err(|()| ProviderCallFailure::Platform)?;
    cache.fresh(stored_at).ok_or(ProviderCallFailure::Platform)
}

async fn invalidate_feishu_tenant_token(credentials: &ProviderCredentials, failed: &SecretText) {
    credentials
        .feishu_tenant_token_cache()
        .await
        .invalidate_if(failed);
}

async fn feishu_active_employee_status<T: ExchangeTransport + Sync>(
    transport: &T,
    tenant_token: &SecretText,
    user_id: &str,
) -> Result<(), ProviderCallFailure> {
    let mut url = Url::parse("https://open.feishu.cn/open-apis/contact/v3/users")
        .expect("fixed Feishu endpoint");
    url.path_segments_mut()
        .expect("fixed Feishu base path")
        .push(user_id);
    url.query_pairs_mut().append_pair("user_id_type", "user_id");
    let response = checked_response(
        transport
            .get_response(&url, Some(tenant_token.as_str()))
            .await
            .map_err(map_exchange_error)?,
    )?;
    let success = response.is_success();
    let mut parsed: FeishuMemberEnvelope = parse_response(&response)?;
    if FEISHU_TENANT_TOKEN_INVALID.contains(&parsed.code) {
        return Err(ProviderCallFailure::TokenInvalid);
    }
    if FEISHU_MEMBER_REJECTED.contains(&parsed.code) {
        return Err(ProviderCallFailure::Rejected);
    }
    if !success {
        return Err(ProviderCallFailure::Platform);
    }
    if parsed.code != 0 {
        return Err(ProviderCallFailure::Platform);
    }
    let status = parsed
        .data
        .take()
        .and_then(|mut data| data.user.take())
        .and_then(|mut user| user.status.take())
        .ok_or(ProviderCallFailure::Rejected)?;
    if status.is_active() {
        Ok(())
    } else {
        Err(ProviderCallFailure::Rejected)
    }
}

async fn verify_feishu<T: ExchangeTransport + Sync>(
    transport: &T,
    credentials: &ProviderCredentials,
    code: &str,
) -> Result<MemberIdentity, VerifyError> {
    let feishu = credentials.feishu().ok_or(VerifyError::Platform)?;
    let user_token = feishu_user_token(transport, credentials, feishu, code)
        .await
        .map_err(VerifyError::from)?;
    let user_id = feishu_employee_id(transport, feishu, &user_token)
        .await
        .map_err(VerifyError::from)?;
    let mut tenant_token = feishu_tenant_access_token(transport, credentials, feishu)
        .await
        .map_err(VerifyError::from)?;
    let mut refreshed = false;
    loop {
        match feishu_active_employee_status(transport, &tenant_token, &user_id).await {
            Ok(()) => return member_identity(&user_id),
            Err(ProviderCallFailure::TokenInvalid) if !refreshed => {
                invalidate_feishu_tenant_token(credentials, &tenant_token).await;
                tenant_token = feishu_tenant_access_token(transport, credentials, feishu)
                    .await
                    .map_err(VerifyError::from)?;
                refreshed = true;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Member verification failures; every variant fails closed.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("the enterprise provider exchange failed or was unconfirmable")]
    Platform,
    #[error("the authorizing user is not an active member of the enterprise")]
    Rejected,
    #[error("the enterprise provider response exceeded the bounded size")]
    ResponseTooLarge,
    #[error("the enterprise authorization code is malformed or too large")]
    InvalidCode,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        EnterpriseAuthProvider, ExchangeError, ExchangeResponse, ExchangeTransport, FeishuProvider,
        MAX_AUTHORIZATION_CODE_BYTES, MAX_EXCHANGE_RESPONSE_BYTES, VerifyError, WeComProvider,
        verify_member,
    };
    use crate::provider::{
        FeishuCredentials, ProviderCredentials, ProviderField, SecretText, WeComCredentials,
    };
    use std::collections::VecDeque;
    use std::future::Future;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use url::Url;
    use yonder_core::EnterpriseProvider;
    use zeroize::Zeroize;

    fn wecom() -> WeComCredentials {
        WeComCredentials {
            corp_id: SecretText::new("ww1234567890abcdef".into(), ProviderField::CorpId).unwrap(),
            agent_id: 7,
            app_secret: SecretText::new("wecom-secret".into(), ProviderField::AppSecret).unwrap(),
        }
    }

    fn feishu() -> FeishuCredentials {
        FeishuCredentials {
            app_id: SecretText::new("cli_abc123".into(), ProviderField::AppId).unwrap(),
            app_secret: SecretText::new("feishu-secret".into(), ProviderField::AppSecret).unwrap(),
            tenant_key: SecretText::new("tenant-abc".into(), ProviderField::TenantKey).unwrap(),
        }
    }

    fn credentials() -> ProviderCredentials {
        ProviderCredentials::from_credentials(Some(wecom()), Some(feishu()))
    }

    #[derive(Debug)]
    enum Request {
        Get { url: String, bearer: Option<String> },
        Post { url: String, body: String },
    }

    struct MockExchange {
        responses: Mutex<VecDeque<Result<ExchangeResponse, ExchangeError>>>,
        requests: Mutex<Vec<Request>>,
    }

    struct CompatibilityExchange {
        post_error: Option<io::ErrorKind>,
    }

    impl ExchangeTransport for CompatibilityExchange {
        async fn get(&self, _url: &Url, _bearer: Option<&str>) -> Result<Vec<u8>, io::Error> {
            Ok(b"get".to_vec())
        }

        async fn post_json(&self, _url: &Url, _body: &str) -> Result<Vec<u8>, io::Error> {
            self.post_error.map_or_else(
                || Ok(b"post".to_vec()),
                |kind| Err(io::Error::new(kind, "sensitive transport detail")),
            )
        }
    }

    impl MockExchange {
        fn new(responses: Vec<Result<ExchangeResponse, ExchangeError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn take(&self, request: Request) -> Result<ExchangeResponse, ExchangeError> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(ExchangeError::from_io(io::Error::other(
                        "unexpected provider request",
                    )))
                })
        }

        fn request_strings(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| match request {
                    Request::Get { url, bearer } => match bearer {
                        Some(token) => format!("Bearer {token} {url}"),
                        None => url.clone(),
                    },
                    Request::Post { url, body } => format!("POST {url} {body}"),
                })
                .collect()
        }
    }

    impl ExchangeTransport for MockExchange {
        fn get(
            &self,
            url: &Url,
            bearer: Option<&str>,
        ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send {
            let request = Request::Get {
                url: url.to_string(),
                bearer: bearer.map(str::to_owned),
            };
            async move {
                self.take(request)
                    .map_err(ExchangeError::into_io)?
                    .into_success_body()
            }
        }

        fn post_json(
            &self,
            url: &Url,
            body: &str,
        ) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send {
            let request = Request::Post {
                url: url.to_string(),
                body: body.to_owned(),
            };
            async move {
                self.take(request)
                    .map_err(ExchangeError::into_io)?
                    .into_success_body()
            }
        }

        fn get_response<'a>(
            &'a self,
            url: &'a Url,
            bearer: Option<&'a str>,
        ) -> impl Future<Output = Result<ExchangeResponse, ExchangeError>> + Send + 'a {
            let request = Request::Get {
                url: url.to_string(),
                bearer: bearer.map(str::to_owned),
            };
            async move { self.take(request) }
        }

        fn post_json_response<'a>(
            &'a self,
            url: &'a Url,
            body: &'a str,
        ) -> impl Future<Output = Result<ExchangeResponse, ExchangeError>> + Send + 'a {
            let request = Request::Post {
                url: url.to_string(),
                body: body.to_owned(),
            };
            async move { self.take(request) }
        }
    }

    fn response(body: &str) -> Result<ExchangeResponse, ExchangeError> {
        http_response(200, body)
    }

    fn http_response(status: u16, body: &str) -> Result<ExchangeResponse, ExchangeError> {
        Ok(ExchangeResponse::new(status, body.as_bytes().to_vec()))
    }

    fn wecom_token(token: &str) -> Result<ExchangeResponse, ExchangeError> {
        response(&format!(
            r#"{{"errcode":0,"errmsg":"ok","access_token":"{token}","expires_in":7200}}"#
        ))
    }

    fn wecom_user(userid: &str) -> Result<ExchangeResponse, ExchangeError> {
        response(&format!(
            r#"{{"errcode":0,"errmsg":"ok","userid":"{userid}"}}"#
        ))
    }

    fn wecom_active() -> Result<ExchangeResponse, ExchangeError> {
        response(r#"{"errcode":0,"errmsg":"ok","status":1}"#)
    }

    fn feishu_oauth(token: &str) -> Result<ExchangeResponse, ExchangeError> {
        response(&format!(
            r#"{{"access_token":"{token}","expires_in":7200,"refresh_token":"ignored","refresh_token_expires_in":2592000,"scope":"auth:user.id:read","token_type":"Bearer"}}"#
        ))
    }

    fn feishu_user(user_id: &str, tenant_key: &str) -> Result<ExchangeResponse, ExchangeError> {
        response(&format!(
            r#"{{"code":0,"msg":"success","data":{{"user_id":"{user_id}","tenant_key":"{tenant_key}"}}}}"#
        ))
    }

    fn feishu_tenant_token(token: &str) -> Result<ExchangeResponse, ExchangeError> {
        response(&format!(
            r#"{{"code":0,"msg":"ok","tenant_access_token":"{token}","expire":7200}}"#
        ))
    }

    fn feishu_status(status: &str) -> Result<ExchangeResponse, ExchangeError> {
        response(&format!(
            r#"{{"code":0,"msg":"success","data":{{"user":{{"status":{status}}}}}}}"#
        ))
    }

    const ACTIVE_STATUS: &str = r#"{"is_activated":true,"is_frozen":false,"is_resigned":false,"is_exited":false,"is_unjoin":false}"#;

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_current_contract_admits_active_member() {
        let exchange = MockExchange::new(vec![
            wecom_token("tok-1"),
            wecom_user("zhang-san"),
            wecom_active(),
        ]);
        let identity = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap();
        assert_eq!(identity.as_bytes(), b"zhang-san");

        let requests = exchange.request_strings();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("https://qyapi.weixin.qq.com/cgi-bin/gettoken?"));
        assert!(requests[0].contains("corpid=ww1234567890abcdef"));
        assert!(requests[0].contains("corpsecret=wecom-secret"));
        assert!(requests[1].contains("/cgi-bin/auth/getuserinfo?"));
        assert!(requests[1].contains("access_token=tok-1"));
        assert!(requests[1].contains("code=auth-code-1"));
        assert!(requests[2].contains("/cgi-bin/user/get?"));
        assert!(requests[2].contains("userid=zhang-san"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_accepts_only_lowercase_userid_and_active_status_one() {
        for body in [
            r#"{"errcode":0,"UserId":"wrong-case"}"#,
            r#"{"errcode":0,"userid":""}"#,
            r#"{"errcode":0,"external_userid":"external"}"#,
        ] {
            let exchange = MockExchange::new(vec![wecom_token("tok-1"), response(body)]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Rejected)
            ));
        }

        for status in [0, 2, 4, 5] {
            let exchange = MockExchange::new(vec![
                wecom_token("tok-1"),
                wecom_user("member"),
                response(&format!(r#"{{"errcode":0,"status":{status}}}"#)),
            ]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Rejected)
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_member_absence_and_remote_anomalies_fail_closed() {
        for body in [
            r#"{"errcode":60111,"errmsg":"not found"}"#,
            r#"{"errcode":0}"#,
        ] {
            let exchange = MockExchange::new(vec![wecom_token("tok-1"), response(body)]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Rejected)
            ));
        }

        let exchange = MockExchange::new(vec![
            wecom_token("tok-1"),
            wecom_user("member"),
            response(r#"{"errcode":99999,"errmsg":"unexpected"}"#),
        ]);
        assert!(matches!(
            verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
            Err(VerifyError::Platform)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn official_user_outcome_codes_are_rejected_without_masking_platform_failures() {
        for code in [40_029, 42_003, 42_022] {
            let exchange = MockExchange::new(vec![
                wecom_token("token"),
                http_response(
                    400,
                    &format!(r#"{{"errcode":{code},"errmsg":"code rejected"}}"#),
                ),
            ]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Rejected)
            ));
        }

        let invisible_wecom_member = MockExchange::new(vec![
            wecom_token("token"),
            wecom_user("member"),
            http_response(403, r#"{"errcode":60021,"errmsg":"member not visible"}"#),
        ]);
        assert!(matches!(
            verify_member(
                &invisible_wecom_member,
                EnterpriseProvider::WeCom,
                "code",
                &credentials()
            )
            .await,
            Err(VerifyError::Rejected)
        ));

        let invisible_wecom_login = MockExchange::new(vec![
            wecom_token("token"),
            http_response(403, r#"{"errcode":60021,"errmsg":"member not visible"}"#),
        ]);
        assert!(matches!(
            verify_member(
                &invisible_wecom_login,
                EnterpriseProvider::WeCom,
                "code",
                &credentials()
            )
            .await,
            Err(VerifyError::Rejected)
        ));

        let invisible_feishu_member = MockExchange::new(vec![
            feishu_oauth("user"),
            feishu_user("member", "tenant-abc"),
            feishu_tenant_token("tenant"),
            http_response(403, r#"{"code":20010,"msg":"permission denied"}"#),
        ]);
        assert!(matches!(
            verify_member(
                &invisible_feishu_member,
                EnterpriseProvider::Feishu,
                "code",
                &credentials()
            )
            .await,
            Err(VerifyError::Rejected)
        ));

        for platform_response in [
            response(r#"{"errcode":40013,"errmsg":"invalid corpid"}"#),
            response(r#"{"errcode":48002,"errmsg":"api forbidden"}"#),
        ] {
            let exchange = MockExchange::new(vec![wecom_token("token"), platform_response]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Platform)
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_current_contract_binds_tenant_and_five_statuses() {
        let exchange = MockExchange::new(vec![
            feishu_oauth("usr-tok"),
            feishu_user("ou_member", "tenant-abc"),
            feishu_tenant_token("tnt-tok"),
            feishu_status(ACTIVE_STATUS),
        ]);
        let identity = verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap();
        assert_eq!(identity.as_bytes(), b"ou_member");

        let requests = exchange.request_strings();
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests[0],
            concat!(
                "POST https://accounts.feishu.cn/oauth/v3/token ",
                r#"{"grant_type":"authorization_code","client_id":"cli_abc123","#,
                r#""client_secret":"feishu-secret","code":"auth-code-1","#,
                r#""redirect_uri":"https://relay.example.test/yonder/callback/feishu"}"#
            )
        );
        assert_eq!(
            requests[1],
            "Bearer usr-tok https://open.feishu.cn/open-apis/authen/v1/user_info"
        );
        assert_eq!(
            requests[2],
            concat!(
                "POST https://open.feishu.cn/open-apis/auth/v3/",
                r#"tenant_access_token/internal {"app_id":"cli_abc123","app_secret":"feishu-secret"}"#
            )
        );
        assert_eq!(
            requests[3],
            "Bearer tnt-tok https://open.feishu.cn/open-apis/contact/v3/users/ou_member?user_id_type=user_id"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_tenant_mismatch_and_external_user_fail_closed_before_directory_access() {
        for response_body in [
            feishu_user("ou_member", "other-tenant"),
            response(r#"{"code":0,"data":{"tenant_key":"tenant-abc"}}"#),
        ] {
            let exchange = MockExchange::new(vec![feishu_oauth("usr-tok"), response_body]);
            assert!(matches!(
                verify_member(
                    &exchange,
                    EnterpriseProvider::Feishu,
                    "code",
                    &credentials()
                )
                .await,
                Err(VerifyError::Rejected)
            ));
            assert_eq!(exchange.request_strings().len(), 2);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_requires_every_current_status_flag() {
        let rejected = [
            r#"{"is_activated":false,"is_frozen":false,"is_resigned":false,"is_exited":false,"is_unjoin":false}"#,
            r#"{"is_activated":true,"is_frozen":true,"is_resigned":false,"is_exited":false,"is_unjoin":false}"#,
            r#"{"is_activated":true,"is_frozen":false,"is_resigned":true,"is_exited":false,"is_unjoin":false}"#,
            r#"{"is_activated":true,"is_frozen":false,"is_resigned":false,"is_exited":true,"is_unjoin":false}"#,
            r#"{"is_activated":true,"is_frozen":false,"is_resigned":false,"is_exited":false,"is_unjoin":true}"#,
            r#"{"is_activated":true,"is_frozen":false,"is_resigned":false,"is_exited":false}"#,
            r#"{}"#,
        ];
        for status in rejected {
            let exchange = MockExchange::new(vec![
                feishu_oauth("usr-tok"),
                feishu_user("ou_member", "tenant-abc"),
                feishu_tenant_token("tnt-tok"),
                feishu_status(status),
            ]);
            assert!(matches!(
                verify_member(
                    &exchange,
                    EnterpriseProvider::Feishu,
                    "code",
                    &credentials()
                )
                .await,
                Err(VerifyError::Rejected)
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn successful_application_tokens_are_reused() {
        let wecom_exchange = MockExchange::new(vec![
            wecom_token("shared"),
            wecom_user("first"),
            wecom_active(),
            wecom_user("second"),
            wecom_active(),
        ]);
        let wecom_credentials = credentials();
        for code in ["one", "two"] {
            verify_member(
                &wecom_exchange,
                EnterpriseProvider::WeCom,
                code,
                &wecom_credentials,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            wecom_exchange
                .request_strings()
                .iter()
                .filter(|request| request.contains("/cgi-bin/gettoken?"))
                .count(),
            1
        );

        let feishu_exchange = MockExchange::new(vec![
            feishu_oauth("user-1"),
            feishu_user("first", "tenant-abc"),
            feishu_tenant_token("shared-tenant"),
            feishu_status(ACTIVE_STATUS),
            feishu_oauth("user-2"),
            feishu_user("second", "tenant-abc"),
            feishu_status(ACTIVE_STATUS),
        ]);
        let feishu_credentials = credentials();
        for code in ["one", "two"] {
            verify_member(
                &feishu_exchange,
                EnterpriseProvider::Feishu,
                code,
                &feishu_credentials,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            feishu_exchange
                .request_strings()
                .iter()
                .filter(|request| request.contains("tenant_access_token/internal"))
                .count(),
            1
        );
    }

    struct ConcurrentWeComExchange {
        token_fetches: AtomicUsize,
    }

    impl ExchangeTransport for ConcurrentWeComExchange {
        async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Vec<u8>, io::Error> {
            self.get_response(url, bearer)
                .await
                .map_err(ExchangeError::into_io)?
                .into_success_body()
        }

        async fn post_json(&self, _url: &Url, _body: &str) -> Result<Vec<u8>, io::Error> {
            Err(io::Error::other("unexpected POST"))
        }

        fn get_response<'a>(
            &'a self,
            url: &'a Url,
            _bearer: Option<&'a str>,
        ) -> impl Future<Output = Result<ExchangeResponse, ExchangeError>> + Send + 'a {
            let path = url.path().to_owned();
            async move {
                match path.as_str() {
                    "/cgi-bin/gettoken" => {
                        self.token_fetches.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        wecom_token("singleflight")
                    }
                    "/cgi-bin/auth/getuserinfo" => wecom_user("member"),
                    "/cgi-bin/user/get" => wecom_active(),
                    _ => Err(ExchangeError::from_io(io::Error::other(
                        "unexpected endpoint",
                    ))),
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_singleflight_to_one_token_fetch() {
        let exchange = Arc::new(ConcurrentWeComExchange {
            token_fetches: AtomicUsize::new(0),
        });
        let credentials = Arc::new(credentials());
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..8 {
            let exchange = Arc::clone(&exchange);
            let credentials = Arc::clone(&credentials);
            tasks.spawn(async move {
                verify_member(
                    exchange.as_ref(),
                    EnterpriseProvider::WeCom,
                    &format!("code-{index}"),
                    credentials.as_ref(),
                )
                .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        assert_eq!(exchange.token_fetches.load(Ordering::SeqCst), 1);
    }

    struct CancelledFetchExchange {
        started: tokio::sync::Notify,
        token_fetches: AtomicUsize,
    }

    impl ExchangeTransport for CancelledFetchExchange {
        async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Vec<u8>, io::Error> {
            self.get_response(url, bearer)
                .await
                .map_err(ExchangeError::into_io)?
                .into_success_body()
        }

        async fn post_json(&self, _url: &Url, _body: &str) -> Result<Vec<u8>, io::Error> {
            Err(io::Error::other("unexpected POST"))
        }

        async fn get_response<'a>(
            &'a self,
            url: &'a Url,
            _bearer: Option<&'a str>,
        ) -> Result<ExchangeResponse, ExchangeError> {
            match url.path() {
                "/cgi-bin/gettoken" => {
                    let fetch = self.token_fetches.fetch_add(1, Ordering::SeqCst);
                    if fetch == 0 {
                        self.started.notify_one();
                        std::future::pending::<()>().await;
                        unreachable!("the first token fetch is cancelled")
                    }
                    wecom_token("after-cancellation")
                }
                "/cgi-bin/auth/getuserinfo" => wecom_user("member"),
                "/cgi-bin/user/get" => wecom_active(),
                _ => Err(ExchangeError::from_io(io::Error::other(
                    "unexpected endpoint",
                ))),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_singleflight_fetch_releases_the_cache_owner() {
        let exchange = Arc::new(CancelledFetchExchange {
            started: tokio::sync::Notify::new(),
            token_fetches: AtomicUsize::new(0),
        });
        let credentials = Arc::new(credentials());
        let task = tokio::spawn({
            let exchange = Arc::clone(&exchange);
            let credentials = Arc::clone(&credentials);
            async move {
                verify_member(
                    exchange.as_ref(),
                    EnterpriseProvider::WeCom,
                    "cancelled",
                    credentials.as_ref(),
                )
                .await
            }
        });
        exchange.started.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        tokio::time::timeout(
            Duration::from_secs(1),
            verify_member(
                exchange.as_ref(),
                EnterpriseProvider::WeCom,
                "retry",
                credentials.as_ref(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(exchange.token_fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_token_fetch_is_not_cached() {
        let exchange = MockExchange::new(vec![
            response(r#"{"errcode":40013,"errmsg":"invalid corpid"}"#),
            wecom_token("recovered"),
            wecom_user("member"),
            wecom_active(),
        ]);
        let credentials = credentials();
        assert!(matches!(
            verify_member(&exchange, EnterpriseProvider::WeCom, "first", &credentials).await,
            Err(VerifyError::Platform)
        ));
        verify_member(&exchange, EnterpriseProvider::WeCom, "second", &credentials)
            .await
            .unwrap();
        assert_eq!(
            exchange
                .request_strings()
                .iter()
                .filter(|request| request.contains("/cgi-bin/gettoken?"))
                .count(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_invalid_token_refreshes_and_retries_only_once() {
        let exchange = MockExchange::new(vec![
            wecom_token("old"),
            http_response(401, r#"{"errcode":40014,"errmsg":"invalid token"}"#),
            wecom_token("new"),
            wecom_user("member"),
            http_response(401, r#"{"errcode":42001,"errmsg":"expired token"}"#),
        ]);
        let shared_credentials = credentials();
        assert!(matches!(
            verify_member(
                &exchange,
                EnterpriseProvider::WeCom,
                "code",
                &shared_credentials,
            )
            .await,
            Err(VerifyError::Platform)
        ));
        assert_eq!(
            exchange
                .request_strings()
                .iter()
                .filter(|request| request.contains("/cgi-bin/gettoken?"))
                .count(),
            2
        );

        let exchange = MockExchange::new(vec![
            wecom_token("old"),
            wecom_user("member"),
            response(r#"{"errcode":40014,"errmsg":"invalid token"}"#),
            wecom_token("new"),
            wecom_active(),
        ]);
        verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials())
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_invalid_tenant_token_refreshes_and_retries_only_once() {
        let exchange = MockExchange::new(vec![
            feishu_oauth("user"),
            feishu_user("member", "tenant-abc"),
            feishu_tenant_token("old"),
            http_response(
                401,
                r#"{"code":99991663,"msg":"invalid tenant access token"}"#,
            ),
            feishu_tenant_token("new"),
            feishu_status(ACTIVE_STATUS),
        ]);
        verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "code",
            &credentials(),
        )
        .await
        .unwrap();

        let exchange = MockExchange::new(vec![
            feishu_oauth("user"),
            feishu_user("member", "tenant-abc"),
            feishu_tenant_token("old"),
            response(r#"{"code":99991665,"msg":"invalid tenant token"}"#),
            feishu_tenant_token("new"),
            response(r#"{"code":99991663,"msg":"expired again"}"#),
        ]);
        assert!(matches!(
            verify_member(
                &exchange,
                EnterpriseProvider::Feishu,
                "code",
                &credentials()
            )
            .await,
            Err(VerifyError::Platform)
        ));
        assert_eq!(
            exchange
                .request_strings()
                .iter()
                .filter(|request| request.contains("tenant_access_token/internal"))
                .count(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_success_bodies_are_typed_without_disclosure() {
        let invalid_grant = MockExchange::new(vec![http_response(
            400,
            r#"{"error":"invalid_grant","error_description":"code expired"}"#,
        )]);
        assert!(matches!(
            verify_member(
                &invalid_grant,
                EnterpriseProvider::Feishu,
                "expired",
                &credentials()
            )
            .await,
            Err(VerifyError::Rejected)
        ));

        let canary = "remote-secret-canary";
        let server_error = MockExchange::new(vec![http_response(
            500,
            &format!(r#"{{"error":"server_error","error_description":"{canary}"}}"#),
        )]);
        let error = verify_member(
            &server_error,
            EnterpriseProvider::Feishu,
            "code",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Platform));
        assert!(!format!("{error:?} {error}").contains(canary));

        let response = ExchangeResponse::new(400, canary.as_bytes().to_vec());
        assert!(!format!("{response:?}").contains(canary));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_schema_and_http_edges_fail_closed() {
        for token_response in [
            http_response(
                500,
                r#"{"errcode":0,"access_token":"token","expires_in":7200}"#,
            ),
            response(r#"{"errcode":0,"access_token":"","expires_in":7200}"#),
            response(r#"{"errcode":0,"access_token":"token","expires_in":0}"#),
            response(&format!(
                r#"{{"errcode":0,"access_token":"{}","expires_in":7200}}"#,
                "x".repeat(4 * 1024 + 1)
            )),
        ] {
            let exchange = MockExchange::new(vec![token_response]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Platform)
            ));
        }

        for member_response in [
            http_response(500, r#"{"errcode":0,"userid":"member"}"#),
            response(r#"{"errcode":42,"errmsg":"unexpected"}"#),
        ] {
            let exchange = MockExchange::new(vec![wecom_token("token"), member_response]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Platform)
            ));
        }

        for status_response in [
            http_response(500, r#"{"errcode":0,"status":1}"#),
            response(r#"{"errcode":0}"#),
        ] {
            let exchange = MockExchange::new(vec![
                wecom_token("token"),
                wecom_user("member"),
                status_response,
            ]);
            let error = verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials())
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                VerifyError::Platform | VerifyError::Rejected
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_schema_http_and_membership_edges_fail_closed() {
        for oauth_response in [
            response(r#"{"code":42,"access_token":"token","expires_in":7200}"#),
            response(r#"{"access_token":"","expires_in":7200}"#),
            response(r#"{"access_token":"token","expires_in":0}"#),
        ] {
            let exchange = MockExchange::new(vec![oauth_response]);
            assert!(matches!(
                verify_member(
                    &exchange,
                    EnterpriseProvider::Feishu,
                    "code",
                    &credentials()
                )
                .await,
                Err(VerifyError::Platform)
            ));
        }

        let user_cases = [
            (
                http_response(
                    500,
                    r#"{"code":0,"data":{"user_id":"member","tenant_key":"tenant-abc"}}"#,
                ),
                false,
            ),
            (response(r#"{"code":99991668,"msg":"expired"}"#), true),
            (response(r#"{"code":42,"msg":"unexpected"}"#), false),
            (response(r#"{"code":0}"#), false),
        ];
        for (user_response, rejected) in user_cases {
            let exchange = MockExchange::new(vec![feishu_oauth("user"), user_response]);
            let error = verify_member(
                &exchange,
                EnterpriseProvider::Feishu,
                "code",
                &credentials(),
            )
            .await
            .unwrap_err();
            assert_eq!(matches!(error, VerifyError::Rejected), rejected);
        }

        for tenant_response in [
            http_response(
                500,
                r#"{"code":0,"tenant_access_token":"token","expire":7200}"#,
            ),
            response(r#"{"code":42,"msg":"unexpected"}"#),
            response(r#"{"code":0,"tenant_access_token":"","expire":7200}"#),
            response(r#"{"code":0,"tenant_access_token":"token","expire":0}"#),
        ] {
            let exchange = MockExchange::new(vec![
                feishu_oauth("user"),
                feishu_user("member", "tenant-abc"),
                tenant_response,
            ]);
            assert!(matches!(
                verify_member(
                    &exchange,
                    EnterpriseProvider::Feishu,
                    "code",
                    &credentials()
                )
                .await,
                Err(VerifyError::Platform)
            ));
        }

        for code in [20_008, 20_010, 20_021, 20_022, 20_023] {
            let exchange = MockExchange::new(vec![
                feishu_oauth("user"),
                feishu_user("member", "tenant-abc"),
                feishu_tenant_token("tenant"),
                response(&format!(r#"{{"code":{code},"msg":"inactive"}}"#)),
            ]);
            assert!(matches!(
                verify_member(
                    &exchange,
                    EnterpriseProvider::Feishu,
                    "code",
                    &credentials()
                )
                .await,
                Err(VerifyError::Rejected)
            ));
        }

        for status_response in [
            http_response(500, r#"{"code":0,"data":{}}"#),
            response(r#"{"code":42,"msg":"unexpected"}"#),
            response(r#"{"code":0,"data":{}}"#),
        ] {
            let exchange = MockExchange::new(vec![
                feishu_oauth("user"),
                feishu_user("member", "tenant-abc"),
                feishu_tenant_token("tenant"),
                status_response,
            ]);
            let error = verify_member(
                &exchange,
                EnterpriseProvider::Feishu,
                "code",
                &credentials(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                error,
                VerifyError::Platform | VerifyError::Rejected
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_feishu_tenant_token_fetch_is_not_cached() {
        let exchange = MockExchange::new(vec![
            feishu_oauth("user-1"),
            feishu_user("first", "tenant-abc"),
            response(r#"{"code":42,"msg":"temporary"}"#),
            feishu_oauth("user-2"),
            feishu_user("second", "tenant-abc"),
            feishu_tenant_token("recovered"),
            feishu_status(ACTIVE_STATUS),
        ]);
        let credentials = credentials();
        assert!(matches!(
            verify_member(&exchange, EnterpriseProvider::Feishu, "first", &credentials,).await,
            Err(VerifyError::Platform)
        ));
        verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "second",
            &credentials,
        )
        .await
        .unwrap();
        assert_eq!(
            exchange
                .request_strings()
                .iter()
                .filter(|request| request.contains("tenant_access_token/internal"))
                .count(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_oversized_and_invalid_inputs_fail_closed() {
        let malformed = MockExchange::new(vec![response("not-json")]);
        assert!(matches!(
            verify_member(
                &malformed,
                EnterpriseProvider::WeCom,
                "code",
                &credentials()
            )
            .await,
            Err(VerifyError::Platform)
        ));

        let oversized = MockExchange::new(vec![Ok(ExchangeResponse::new(
            200,
            vec![0; MAX_EXCHANGE_RESPONSE_BYTES as usize + 1],
        ))]);
        assert!(matches!(
            verify_member(
                &oversized,
                EnterpriseProvider::WeCom,
                "code",
                &credentials()
            )
            .await,
            Err(VerifyError::ResponseTooLarge)
        ));

        let no_requests = MockExchange::new(Vec::new());
        for code in ["", &"x".repeat(MAX_AUTHORIZATION_CODE_BYTES + 1)] {
            assert!(matches!(
                verify_member(
                    &no_requests,
                    EnterpriseProvider::WeCom,
                    code,
                    &credentials()
                )
                .await,
                Err(VerifyError::InvalidCode)
            ));
        }
        assert!(no_requests.request_strings().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_provider_and_invalid_lifetimes_fail_closed() {
        let only_wecom = ProviderCredentials::from_credentials(Some(wecom()), None);
        assert!(matches!(
            verify_member(
                &MockExchange::new(Vec::new()),
                EnterpriseProvider::Feishu,
                "code",
                &only_wecom
            )
            .await,
            Err(VerifyError::Platform)
        ));

        let only_feishu = ProviderCredentials::from_credentials(None, Some(feishu()));
        assert!(matches!(
            verify_member(
                &MockExchange::new(Vec::new()),
                EnterpriseProvider::WeCom,
                "code",
                &only_feishu
            )
            .await,
            Err(VerifyError::Platform)
        ));

        for expires_in in [0, 86_401] {
            let exchange = MockExchange::new(vec![response(&format!(
                r#"{{"errcode":0,"access_token":"token","expires_in":{expires_in}}}"#
            ))]);
            assert!(matches!(
                verify_member(&exchange, EnterpriseProvider::WeCom, "code", &credentials()).await,
                Err(VerifyError::Platform)
            ));
        }
    }

    #[test]
    fn provider_trait_and_secret_zeroization_are_explicit() {
        fn assert_provider<T: EnterpriseAuthProvider>(_provider: &T) {}

        let credentials = credentials();
        assert_provider(&WeComProvider {
            credentials: &credentials,
        });
        assert_provider(&FeishuProvider {
            credentials: &credentials,
        });

        let mut response = ExchangeResponse::new(200, b"token-canary".to_vec());
        response.zeroize();
        assert_eq!(response.status(), 0);
        assert!(response.body().is_empty());
    }

    #[test]
    fn exchange_error_messages_never_include_transport_or_body_secrets() {
        let canary = "transport-secret-canary";
        let transport = ExchangeError::from_io(io::Error::other(canary));
        assert!(!format!("{transport:?} {transport}").contains(canary));
        assert_eq!(
            format!("{:?}", ExchangeError::ResponseTooLarge),
            "ResponseTooLarge"
        );

        for error in [
            VerifyError::Platform,
            VerifyError::Rejected,
            VerifyError::ResponseTooLarge,
            VerifyError::InvalidCode,
        ] {
            assert!(!format!("{error:?} {error}").contains(canary));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn compatibility_transport_preserves_post_success_and_error_semantics() {
        let url = Url::parse("https://provider.example.test/token").unwrap();
        let success = CompatibilityExchange { post_error: None }
            .post_json_response(&url, "{}")
            .await
            .unwrap();
        assert_eq!(success.status(), 200);
        assert_eq!(success.body(), b"post");

        let error = CompatibilityExchange {
            post_error: Some(io::ErrorKind::TimedOut),
        }
        .post_json_response(&url, "{}")
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ExchangeError::Transport(io::ErrorKind::TimedOut)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_provider_exchange_stage_fails_closed_on_transport_errors() {
        let transport_error = || {
            Err(ExchangeError::from_io(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "sensitive transport detail",
            )))
        };
        let cases = [
            (
                EnterpriseProvider::WeCom,
                vec![wecom_token("token"), transport_error()],
            ),
            (
                EnterpriseProvider::WeCom,
                vec![
                    wecom_token("token"),
                    wecom_user("member"),
                    transport_error(),
                ],
            ),
            (
                EnterpriseProvider::Feishu,
                vec![feishu_oauth("user"), transport_error()],
            ),
            (
                EnterpriseProvider::Feishu,
                vec![
                    feishu_oauth("user"),
                    feishu_user("member", "tenant-abc"),
                    transport_error(),
                ],
            ),
            (
                EnterpriseProvider::Feishu,
                vec![
                    feishu_oauth("user"),
                    feishu_user("member", "tenant-abc"),
                    feishu_tenant_token("tenant"),
                    transport_error(),
                ],
            ),
        ];
        for (provider, responses) in cases {
            assert!(matches!(
                verify_member(
                    &MockExchange::new(responses),
                    provider,
                    "code",
                    &credentials()
                )
                .await,
                Err(VerifyError::Platform)
            ));
        }

        let oversized = MockExchange::new(vec![Err(ExchangeError::ResponseTooLarge)]);
        assert!(matches!(
            verify_member(
                &oversized,
                EnterpriseProvider::WeCom,
                "code",
                &credentials()
            )
            .await,
            Err(VerifyError::ResponseTooLarge)
        ));
    }
}
