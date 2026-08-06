//! Bounded enterprise member verification via provider OAuth exchange.
//!
//! Verifies an OAuth authorization code on the provider platform and
//! confirms the authorizing user is still an active internal member of
//! the configured enterprise (design section 6). Every failure fails
//! closed: provider anomalies, external users, departed or disabled
//! members and unconfirmable states never admit. Member identity bytes
//! are bounded and returned to the session, which destroys them once
//! membership has been validated.

use crate::provider::{FeishuCredentials, ProviderCredentials, WeComCredentials};
use crate::session::MemberIdentity;
use serde_json::Value;
use thiserror::Error;
use url::Url;
use yonder_core::EnterpriseProvider;

/// Bound on one provider API response body.
pub const MAX_EXCHANGE_RESPONSE_BYTES: u64 = 64 * 1024;
/// Bound on the OAuth authorization code.
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 512;

/// Minimal outbound exchange transport, injectable for tests.
///
/// Implementations must cap response bodies at `MAX_EXCHANGE_RESPONSE_BYTES`;
/// the verifier re-checks the bound before parsing. The real transport is a
/// bounded hyper client; the `Send` future bound keeps the exchange
/// spawnable inside tokio tasks.
pub trait ExchangeTransport {
    /// Executes a GET request with an optional bearer token.
    fn get(
        &self,
        url: &Url,
        bearer: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, std::io::Error>> + Send;
    /// Executes a JSON POST request.
    fn post_json(
        &self,
        url: &Url,
        body: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, std::io::Error>> + Send;
}

/// Verifies the OAuth authorization code against the provider and
/// confirms the authorizing user is an active member of the enterprise.
pub async fn verify_member<T: ExchangeTransport>(
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
            let wecom = credentials.wecom().ok_or(VerifyError::Platform)?;
            verify_wecom(transport, wecom, code).await
        }
        EnterpriseProvider::Feishu => {
            let feishu = credentials.feishu().ok_or(VerifyError::Platform)?;
            verify_feishu(transport, feishu, code).await
        }
    }
}

/// WeCom (企业微信): app token, web-authorization member id, member status.
async fn verify_wecom<T: ExchangeTransport>(
    transport: &T,
    credentials: &WeComCredentials,
    code: &str,
) -> Result<MemberIdentity, VerifyError> {
    let token = wecom_access_token(transport, credentials).await?;
    let userid = wecom_member_userid(transport, &token, code).await?;
    wecom_active_member_status(transport, &token, &userid).await?;
    member_identity(&userid)
}

/// Feishu (飞书): user token, employee id, tenant token, employee status.
async fn verify_feishu<T: ExchangeTransport>(
    transport: &T,
    credentials: &FeishuCredentials,
    code: &str,
) -> Result<MemberIdentity, VerifyError> {
    let user_token = feishu_user_token(transport, credentials, code).await?;
    let user_id = feishu_employee_id(transport, &user_token).await?;
    let tenant_token = feishu_tenant_access_token(transport, credentials).await?;
    feishu_active_employee_status(transport, &tenant_token, &user_id).await?;
    member_identity(&user_id)
}

fn member_identity(user_id: &str) -> Result<MemberIdentity, VerifyError> {
    MemberIdentity::new(user_id.as_bytes()).map_err(|_| VerifyError::Platform)
}

fn bounded_body(body: Vec<u8>) -> Result<Vec<u8>, VerifyError> {
    if u64::try_from(body.len()).map_or(true, |len| len > MAX_EXCHANGE_RESPONSE_BYTES) {
        return Err(VerifyError::ResponseTooLarge);
    }
    Ok(body)
}

fn json(body: Vec<u8>) -> Result<Value, VerifyError> {
    serde_json::from_slice(&body).map_err(|_| VerifyError::Platform)
}

/// WeCom reports failures through `errcode`; zero means success.
fn wecom_success(value: &Value) -> bool {
    value.get("errcode").and_then(Value::as_i64) == Some(0)
}

fn wecom_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// Feishu reports failures through `code`; zero means success.
fn feishu_success(value: &Value) -> bool {
    value.get("code").and_then(Value::as_i64) == Some(0)
}

/// A non-empty string field, found either flat or under the `data`
/// envelope (the Feishu tenant-token response is flat; the user-token and
/// user-info responses are nested).
fn feishu_token<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .or_else(|| value.get("data")?.get(field))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

async fn wecom_access_token<T: ExchangeTransport>(
    transport: &T,
    credentials: &WeComCredentials,
) -> Result<String, VerifyError> {
    let mut url =
        Url::parse("https://qyapi.weixin.qq.com/cgi-bin/gettoken").expect("fixed wecom endpoint");
    url.query_pairs_mut()
        .append_pair("corpid", credentials.corp_id.as_str())
        .append_pair("corpsecret", credentials.app_secret.as_str());
    let body = bounded_body(transport.get(&url, None).await.map_err(|_| VerifyError::Platform)?)?;
    let value = json(body)?;
    if !wecom_success(&value) {
        return Err(VerifyError::Platform);
    }
    wecom_string(&value, "access_token")
        .map(str::to_owned)
        .ok_or(VerifyError::Platform)
}

async fn wecom_member_userid<T: ExchangeTransport>(
    transport: &T,
    token: &str,
    code: &str,
) -> Result<String, VerifyError> {
    let mut url =
        Url::parse("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo")
            .expect("fixed wecom endpoint");
    url.query_pairs_mut()
        .append_pair("access_token", token)
        .append_pair("code", code);
    let body = bounded_body(transport.get(&url, None).await.map_err(|_| VerifyError::Platform)?)?;
    let value = json(body)?;
    match value.get("errcode").and_then(Value::as_i64) {
        Some(0) => {}
        Some(60111) => return Err(VerifyError::Rejected), // 成员不存在（已离职）
        _ => return Err(VerifyError::Platform),
    }
    // External contacts and users of other enterprises carry no userid.
    wecom_string(&value, "userid")
        .map(str::to_owned)
        .ok_or(VerifyError::Rejected)
}

async fn wecom_active_member_status<T: ExchangeTransport>(
    transport: &T,
    token: &str,
    userid: &str,
) -> Result<(), VerifyError> {
    let mut url =
        Url::parse("https://qyapi.weixin.qq.com/cgi-bin/user/get").expect("fixed wecom endpoint");
    url.query_pairs_mut()
        .append_pair("access_token", token)
        .append_pair("userid", userid);
    let body = bounded_body(transport.get(&url, None).await.map_err(|_| VerifyError::Platform)?)?;
    let value = json(body)?;
    match value.get("errcode").and_then(Value::as_i64) {
        // Status 1 is an activated active member; disabled, not-activated,
        // exited and unconfirmable statuses are rejected.
        Some(0) => {
            if value.get("status").and_then(Value::as_i64) == Some(1) {
                Ok(())
            } else {
                Err(VerifyError::Rejected)
            }
        }
        Some(60111) => Err(VerifyError::Rejected), // 成员已离职或不存在
        _ => Err(VerifyError::Platform),
    }
}

async fn feishu_user_token<T: ExchangeTransport>(
    transport: &T,
    credentials: &FeishuCredentials,
    code: &str,
) -> Result<String, VerifyError> {
    let url =
        Url::parse("https://open.feishu.cn/open-apis/authen/v1/oidc/access_token")
            .expect("fixed feishu endpoint");
    let body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "client_id": credentials.app_id.as_str(),
        "client_secret": credentials.app_secret.as_str(),
    })
    .to_string();
    let response = bounded_body(
        transport
            .post_json(&url, &body)
            .await
            .map_err(|_| VerifyError::Platform)?,
    )?;
    let value = json(response)?;
    if !feishu_success(&value) {
        return Err(VerifyError::Platform);
    }
    feishu_token(&value, "access_token")
        .map(str::to_owned)
        .ok_or(VerifyError::Platform)
}

async fn feishu_employee_id<T: ExchangeTransport>(
    transport: &T,
    user_token: &str,
) -> Result<String, VerifyError> {
    let url =
        Url::parse("https://open.feishu.cn/open-apis/authen/v1/user_info")
            .expect("fixed feishu endpoint");
    let body = bounded_body(
        transport
            .get(&url, Some(user_token))
            .await
            .map_err(|_| VerifyError::Platform)?,
    )?;
    let value = json(body)?;
    if !feishu_success(&value) {
        return Err(VerifyError::Platform);
    }
    // The employee user_id is only present for members of the enterprise.
    feishu_token(&value, "user_id")
        .map(str::to_owned)
        .ok_or(VerifyError::Rejected)
}

async fn feishu_tenant_access_token<T: ExchangeTransport>(
    transport: &T,
    credentials: &FeishuCredentials,
) -> Result<String, VerifyError> {
    let url =
        Url::parse("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal")
            .expect("fixed feishu endpoint");
    let body = serde_json::json!({
        "app_id": credentials.app_id.as_str(),
        "app_secret": credentials.app_secret.as_str(),
    })
    .to_string();
    let response = bounded_body(
        transport
            .post_json(&url, &body)
            .await
            .map_err(|_| VerifyError::Platform)?,
    )?;
    let value = json(response)?;
    if !feishu_success(&value) {
        return Err(VerifyError::Platform);
    }
    feishu_token(&value, "tenant_access_token")
        .map(str::to_owned)
        .ok_or(VerifyError::Platform)
}

async fn feishu_active_employee_status<T: ExchangeTransport>(
    transport: &T,
    tenant_token: &str,
    user_id: &str,
) -> Result<(), VerifyError> {
    let mut url =
        Url::parse("https://open.feishu.cn/open-apis/contact/v3/users")
            .expect("fixed feishu endpoint");
    url.path_segments_mut()
        .expect("fixed feishu base path")
        .push(user_id);
    url.query_pairs_mut().append_pair("user_id_type", "user_id");
    let body = bounded_body(
        transport
            .get(&url, Some(tenant_token))
            .await
            .map_err(|_| VerifyError::Platform)?,
    )?;
    let value = json(body)?;
    if !feishu_success(&value) {
        // The member status cannot be confirmed; reject fail-closed.
        return Err(VerifyError::Rejected);
    }
    // employee_status 1 is an active employee; departed, pending and
    // unconfirmable statuses are rejected.
    let active = value
        .get("data")
        .and_then(|data| data.get("user"))
        .and_then(|user| user.get("employee_status"))
        .and_then(Value::as_i64);
    if active == Some(1) {
        Ok(())
    } else {
        Err(VerifyError::Rejected)
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
        MAX_AUTHORIZATION_CODE_BYTES, MAX_EXCHANGE_RESPONSE_BYTES, VerifyError, verify_member,
    };
    use crate::provider::{
        FeishuCredentials, ProviderCredentials, ProviderField, SecretText, WeComCredentials,
    };
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;
    use url::Url;
    use yonder_core::EnterpriseProvider;

    fn wecom() -> WeComCredentials {
        WeComCredentials {
            corp_id: SecretText::new("ww1234567890abcdef".into(), ProviderField::CorpId).unwrap(),
            agent_id: 7,
            app_secret: SecretText::new("s3cret".into(), ProviderField::AppSecret).unwrap(),
        }
    }

    fn feishu() -> FeishuCredentials {
        FeishuCredentials {
            app_id: SecretText::new("cli_abc123".into(), ProviderField::AppId).unwrap(),
            app_secret: SecretText::new("s3cret".into(), ProviderField::AppSecret).unwrap(),
        }
    }

    fn credentials() -> ProviderCredentials {
        ProviderCredentials::from_credentials(Some(wecom()), Some(feishu()))
    }

    struct MockExchange {
        responses: Mutex<VecDeque<Result<Vec<u8>, io::Error>>>,
        requests: Mutex<Vec<String>>,
    }

    impl MockExchange {
        fn new(responses: Vec<Result<Vec<u8>, io::Error>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn take(&self, request: String) -> Result<Vec<u8>, io::Error> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::other("unexpected provider request")))
        }
    }

    impl super::ExchangeTransport for MockExchange {
        fn get(
            &self,
            url: &Url,
            bearer: Option<&str>,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            let request = match bearer {
                Some(token) => format!("Bearer {token} {url}"),
                None => url.to_string(),
            };
            async move { self.take(request) }
        }

        fn post_json(
            &self,
            url: &Url,
            body: &str,
        ) -> impl std::future::Future<Output = Result<Vec<u8>, io::Error>> + Send {
            let request = format!("POST {url} {body}");
            async move { self.take(request) }
        }
    }

    fn ok(response: &str) -> Result<Vec<u8>, io::Error> {
        Ok(response.as_bytes().to_vec())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_happy_path_admits_active_member() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san","name":"张三","status":1}"#),
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
        let requests = exchange.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("https://qyapi.weixin.qq.com/cgi-bin/gettoken?"));
        assert!(requests[0].contains("corpid=ww1234567890abcdef"));
        assert!(requests[0].contains("corpsecret=s3cret"));
        assert!(requests[1]
            .starts_with("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?"));
        assert!(requests[1].contains("access_token=tok-1"));
        assert!(requests[1].contains("code=auth-code-1"));
        assert!(requests[2].starts_with("https://qyapi.weixin.qq.com/cgi-bin/user/get?"));
        assert!(requests[2].contains("userid=zhang-san"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_external_contact_is_rejected() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","external_userid":"wo_12345"}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_departed_member_is_rejected() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":60111,"errmsg":"userid not found"}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));

        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":60111,"errmsg":"userid not found"}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_disabled_member_is_rejected() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san","status":2}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_unconfirmable_status_is_rejected() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
            ok(r#"{"errcode":0,"errmsg":"ok","userid":"zhang-san"}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_platform_failure_is_fail_closed() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":40013,"errmsg":"invalid corpid"}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Platform));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wecom_oversized_identity_is_fail_closed() {
        let oversized_userid = format!(r#"{{"errcode":0,"errmsg":"ok","userid":"{}"}}"#, "x".repeat(300));
        let exchange = MockExchange::new(vec![
            ok(r#"{"errcode":0,"errmsg":"ok","access_token":"tok-1","expires_in":7200}"#),
            ok(&oversized_userid),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Platform));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_provider_responses_are_rejected() {
        let mut body = br#"{"errcode":0,"errmsg":"ok","access_token":""#.to_vec();
        body.extend(vec![b'x'; (MAX_EXCHANGE_RESPONSE_BYTES + 1) as usize]);
        body.extend_from_slice(b"\"}");
        let exchange = MockExchange::new(vec![Ok(body)]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::ResponseTooLarge));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transport_failure_is_fail_closed() {
        let exchange = MockExchange::new(vec![Err(io::Error::other("network unreachable"))]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::WeCom,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Platform));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_happy_path_admits_active_member() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"code":0,"data":{"access_token":"usr-tok","expires_in":7200,"refresh_token":"r","token_type":"Bearer"}}"#),
            ok(r#"{"code":0,"data":{"open_id":"ou_123","user_id":"cli_user_7","enterprise_email":"u@corp.test"}}"#),
            ok(r#"{"code":0,"tenant_access_token":"tnt-tok","expire":7200}"#),
            ok(r#"{"code":0,"data":{"user":{"user_id":"cli_user_7","employee_status":1}}}"#),
        ]);
        let identity = verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap();
        assert_eq!(identity.as_bytes(), b"cli_user_7");
        let requests = exchange.requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[0]
            .starts_with("POST https://open.feishu.cn/open-apis/authen/v1/oidc/access_token "));
        assert!(requests[0].contains("\"code\":\"auth-code-1\""));
        assert!(requests[0].contains("\"client_id\":\"cli_abc123\""));
        assert!(requests[1]
            .starts_with("Bearer usr-tok https://open.feishu.cn/open-apis/authen/v1/user_info"));
        assert!(requests[2]
            .starts_with("POST https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal "));
        assert!(requests[3].starts_with("Bearer tnt-tok "));
        assert!(requests[3].contains("/contact/v3/users/cli_user_7?user_id_type=user_id"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_user_without_employee_id_is_rejected() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"code":0,"data":{"access_token":"usr-tok","expires_in":7200,"refresh_token":"r","token_type":"Bearer"}}"#),
            ok(r#"{"code":0,"data":{"open_id":"ou_123"}}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_departed_member_is_rejected() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"code":0,"data":{"access_token":"usr-tok","expires_in":7200,"refresh_token":"r","token_type":"Bearer"}}"#),
            ok(r#"{"code":0,"data":{"open_id":"ou_123","user_id":"cli_user_7"}}"#),
            ok(r#"{"code":0,"tenant_access_token":"tnt-tok","expire":7200}"#),
            ok(r#"{"code":0,"data":{"user":{"user_id":"cli_user_7","employee_status":2}}}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_unconfirmable_status_is_rejected() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"code":0,"data":{"access_token":"usr-tok","expires_in":7200,"refresh_token":"r","token_type":"Bearer"}}"#),
            ok(r#"{"code":0,"data":{"open_id":"ou_123","user_id":"cli_user_7"}}"#),
            ok(r#"{"code":0,"tenant_access_token":"tnt-tok","expire":7200}"#),
            ok(r#"{"code":99991663,"msg":"user not found"}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Rejected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn feishu_tenant_token_failure_is_platform() {
        let exchange = MockExchange::new(vec![
            ok(r#"{"code":0,"data":{"access_token":"usr-tok","expires_in":7200,"refresh_token":"r","token_type":"Bearer"}}"#),
            ok(r#"{"code":0,"data":{"open_id":"ou_123","user_id":"cli_user_7"}}"#),
            ok(r#"{"code":10003,"msg":"invalid app_secret"}"#),
        ]);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "auth-code-1",
            &credentials(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Platform));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authorization_codes_are_bounded() {
        let exchange = MockExchange::new(vec![]);
        assert!(matches!(
            verify_member(&exchange, EnterpriseProvider::WeCom, "", &credentials()).await,
            Err(VerifyError::InvalidCode)
        ));
        assert!(matches!(
            verify_member(
                &exchange,
                EnterpriseProvider::WeCom,
                &"x".repeat(MAX_AUTHORIZATION_CODE_BYTES + 1),
                &credentials()
            )
            .await,
            Err(VerifyError::InvalidCode)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unconfigured_provider_is_fail_closed() {
        let exchange = MockExchange::new(vec![]);
        let only_wecom = ProviderCredentials::from_credentials(Some(wecom()), None);
        let error = verify_member(
            &exchange,
            EnterpriseProvider::Feishu,
            "auth-code-1",
            &only_wecom,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VerifyError::Platform));
    }
}
