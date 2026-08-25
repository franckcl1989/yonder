//! Enterprise provider credentials and OAuth authorization URL building.
//!
//! Secrets live in per-platform sensitive files loaded once at startup
//! (design section 7): never plaintext in configuration, no hot reload.
//! The platform credential documents are protected with the same
//! `SecretFilePolicy` used for the relay identity and WSS key.

use crate::enterprise::CallbackExternalUrl;
use crate::secret_file::{SecretFileError, SecretFilePolicy, SystemSecretFilePolicy};
use crate::session::{OAuthState, TransitionError};
use config::FileFormat;
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{Mutex, MutexGuard};
use url::Url;
use yonder_core::wire::enterprise::AuthorizationUrl;
use yonder_core::{EnterpriseProvider, EnterpriseProviders};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bound on one provider secret file document.
pub const MAX_PROVIDER_SECRET_BYTES: u64 = 16 * 1024;
/// Bound on a corporate identifier (`corp_id`, `app_id`).
pub const MAX_CREDENTIAL_ID_BYTES: usize = 64;
/// Bound on an application secret.
pub const MAX_APP_SECRET_BYTES: usize = 512;
/// Bound on the Feishu tenant key configured for this relay.
pub const MAX_TENANT_KEY_BYTES: usize = 128;
/// Bound on an application access token returned by a provider.
pub(crate) const MAX_PROVIDER_TOKEN_BYTES: usize = 4 * 1024;
/// Provider token lifetimes beyond one day are rejected as anomalous.
pub(crate) const MAX_PROVIDER_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Cached tokens are retired before their provider-reported expiry.
const MAX_TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

/// The WeCom (企业微信) self-built application credentials.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WeComCredentials {
    /// The enterprise corporate identifier.
    pub(crate) corp_id: SecretText,
    /// The self-built application agent identifier.
    pub(crate) agent_id: u32,
    /// The self-built application secret.
    pub(crate) app_secret: SecretText,
}

impl fmt::Debug for WeComCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WeComCredentials")
            .field("corp_id", &Redacted)
            .field("agent_id", &self.agent_id)
            .field("app_secret", &Redacted)
            .finish()
    }
}

/// The Feishu (飞书) enterprise self-built application credentials.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FeishuCredentials {
    /// The application identifier.
    pub(crate) app_id: SecretText,
    /// The application secret.
    pub(crate) app_secret: SecretText,
    /// The tenant that is permitted to authorize this relay.
    pub(crate) tenant_key: SecretText,
}

impl fmt::Debug for FeishuCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeishuCredentials")
            .field("app_id", &Redacted)
            .field("app_secret", &Redacted)
            .field("tenant_key", &Redacted)
            .finish()
    }
}

/// A zeroizing credential text.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretText(String);

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        Redacted.fmt(formatter)
    }
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl SecretText {
    pub(crate) fn new(mut value: String, kind: ProviderField) -> Result<Self, ProviderError> {
        let bound = match kind {
            ProviderField::CorpId | ProviderField::AppId => MAX_CREDENTIAL_ID_BYTES,
            ProviderField::TenantKey => MAX_TENANT_KEY_BYTES,
            ProviderField::AgentId | ProviderField::AppSecret => MAX_APP_SECRET_BYTES,
            ProviderField::AccessToken => MAX_PROVIDER_TOKEN_BYTES,
        };
        if value.is_empty() || value.len() > bound || value.chars().any(char::is_whitespace) {
            value.zeroize();
            return Err(ProviderError::InvalidCredential(kind));
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The credentials of every enabled provider, loaded once at startup.
pub struct ProviderCredentials {
    wecom: Option<WeComCredentials>,
    feishu: Option<FeishuCredentials>,
    callback_url: CallbackExternalUrl,
    wecom_token: Mutex<ProviderTokenCache>,
    feishu_tenant_token: Mutex<ProviderTokenCache>,
}

impl fmt::Debug for ProviderCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentials")
            .field("wecom_configured", &self.wecom.is_some())
            .field("feishu_configured", &self.feishu.is_some())
            .field("callback_url", &self.callback_url)
            .field("token_caches", &Redacted)
            .finish()
    }
}

/// One fixed-capacity provider-token cache entry.
pub(crate) struct ProviderTokenCache {
    entry: Option<CachedProviderToken>,
}

struct CachedProviderToken {
    value: SecretText,
    usable_until: Instant,
}

impl ProviderTokenCache {
    const fn empty() -> Self {
        Self { entry: None }
    }

    /// Returns a zeroizing temporary token only while the monotonic
    /// early-expiry boundary remains in the future.
    pub(crate) fn fresh(&mut self, now: Instant) -> Option<SecretText> {
        if self
            .entry
            .as_ref()
            .is_some_and(|entry| now >= entry.usable_until)
        {
            self.entry = None;
        }
        self.entry.as_ref().map(|entry| entry.value.clone())
    }

    /// Stores exactly one token and rejects anomalous provider lifetimes.
    pub(crate) fn store(
        &mut self,
        value: SecretText,
        expires_in: Duration,
        now: Instant,
    ) -> Result<(), ()> {
        if expires_in.is_zero() || expires_in > MAX_PROVIDER_TOKEN_TTL {
            return Err(());
        }
        let proportional_margin = expires_in / 10;
        let margin = proportional_margin.min(MAX_TOKEN_REFRESH_MARGIN);
        let usable_for = expires_in.checked_sub(margin).ok_or(())?;
        let usable_until = now.checked_add(usable_for).ok_or(())?;
        self.entry = Some(CachedProviderToken {
            value,
            usable_until,
        });
        Ok(())
    }

    /// Invalidates only the token that actually failed. A concurrent
    /// refresh therefore cannot be erased by a late response for an older
    /// token.
    pub(crate) fn invalidate_if(&mut self, failed: &SecretText) {
        if self
            .entry
            .as_ref()
            .is_some_and(|entry| entry.value == *failed)
        {
            self.entry = None;
        }
    }
}

impl ProviderCredentials {
    /// Loads the secret file of every enabled provider and validates the
    /// credential documents. Fails closed on any enabled provider.
    pub fn load(config: &crate::enterprise::EnterpriseAuthConfig) -> Result<Self, ProviderError> {
        let mut wecom = None;
        let mut feishu = None;
        for provider in config.providers().iter() {
            let path = config
                .secret_path(provider)
                .ok_or(ProviderError::MissingSecretPath(provider))?;
            let document = load_secret_document(path)?;
            match provider {
                EnterpriseProvider::WeCom => wecom = Some(parse_wecom(path, document)?),
                EnterpriseProvider::Feishu => feishu = Some(parse_feishu(path, document)?),
            }
        }
        Ok(Self::with_callback(
            wecom,
            feishu,
            config.callback_external().clone(),
        ))
    }

    /// The WeCom credentials when WeCom is configured.
    pub(crate) const fn wecom(&self) -> Option<&WeComCredentials> {
        self.wecom.as_ref()
    }

    /// The Feishu credentials when Feishu is configured.
    pub(crate) const fn feishu(&self) -> Option<&FeishuCredentials> {
        self.feishu.as_ref()
    }

    /// The exact Feishu redirect URI used during both authorization and
    /// OAuth v3 code exchange.
    pub(crate) fn feishu_redirect_uri(&self) -> Url {
        redirect_uri(&self.callback_url, EnterpriseProvider::Feishu)
    }

    /// Acquires the WeCom application-token singleflight/cache.
    pub(crate) async fn wecom_token_cache(&self) -> MutexGuard<'_, ProviderTokenCache> {
        self.wecom_token.lock().await
    }

    /// Acquires the Feishu tenant-token singleflight/cache.
    pub(crate) async fn feishu_tenant_token_cache(&self) -> MutexGuard<'_, ProviderTokenCache> {
        self.feishu_tenant_token.lock().await
    }

    /// Constructs credentials directly for crate-internal tests.
    #[cfg(test)]
    pub(crate) fn from_credentials(
        wecom: Option<WeComCredentials>,
        feishu: Option<FeishuCredentials>,
    ) -> Self {
        let callback_url = CallbackExternalUrl::new(
            Url::parse("https://relay.example.test").expect("fixed test callback URL"),
        )
        .expect("valid fixed test callback URL");
        Self::with_callback(wecom, feishu, callback_url)
    }

    fn with_callback(
        wecom: Option<WeComCredentials>,
        feishu: Option<FeishuCredentials>,
        callback_url: CallbackExternalUrl,
    ) -> Self {
        Self {
            wecom,
            feishu,
            callback_url,
            wecom_token: Mutex::new(ProviderTokenCache::empty()),
            feishu_tenant_token: Mutex::new(ProviderTokenCache::empty()),
        }
    }

    /// The set of providers with loaded credentials.
    pub fn providers(&self) -> Result<EnterpriseProviders, ProviderError> {
        EnterpriseProviders::new(self.wecom.is_some(), self.feishu.is_some())
            .map_err(|_| ProviderError::NoCredentials)
    }

    /// Builds the provider authorization URL bound to a single-use state.
    pub fn authorization_url(
        &self,
        provider: EnterpriseProvider,
        callback_url: &CallbackExternalUrl,
        state: &OAuthState,
    ) -> Result<AuthorizationUrl, ProviderError> {
        let url = match provider {
            EnterpriseProvider::WeCom => {
                let wecom = self
                    .wecom
                    .as_ref()
                    .ok_or(ProviderError::NotConfigured(provider))?;
                wecom_authorization_url(wecom, callback_url, state)
            }
            EnterpriseProvider::Feishu => {
                let feishu = self
                    .feishu
                    .as_ref()
                    .ok_or(ProviderError::NotConfigured(provider))?;
                feishu_authorization_url(feishu, callback_url, state)
            }
        };
        AuthorizationUrl::new(url.as_str()).map_err(|_| ProviderError::AuthorizationUrl)
    }
}

/// The canonical callback path of one provider.
#[must_use]
pub const fn callback_path(provider: EnterpriseProvider) -> &'static str {
    match provider {
        EnterpriseProvider::WeCom => "/yonder/callback/wecom",
        EnterpriseProvider::Feishu => "/yonder/callback/feishu",
    }
}

/// Builds the OAuth redirect URI of one provider.
fn redirect_uri(base: &CallbackExternalUrl, provider: EnterpriseProvider) -> Url {
    let mut url = base.as_url().clone();
    url.set_path(callback_path(provider));
    url
}

fn wecom_authorization_url(
    wecom: &WeComCredentials,
    callback: &CallbackExternalUrl,
    state: &OAuthState,
) -> Url {
    let mut url = Url::parse("https://login.work.weixin.qq.com/wwlogin/sso/login")
        .expect("fixed wecom authorize endpoint");
    url.query_pairs_mut()
        .append_pair("login_type", "CorpApp")
        .append_pair("appid", wecom.corp_id.as_str())
        .append_pair("agentid", &wecom.agent_id.to_string())
        .append_pair(
            "redirect_uri",
            redirect_uri(callback, EnterpriseProvider::WeCom).as_str(),
        )
        .append_pair("state", &encode_state(state));
    url
}

fn feishu_authorization_url(
    feishu: &FeishuCredentials,
    callback: &CallbackExternalUrl,
    state: &OAuthState,
) -> Url {
    let mut url = Url::parse("https://accounts.feishu.cn/open-apis/authen/v1/authorize")
        .expect("fixed feishu authorize endpoint");
    url.query_pairs_mut()
        .append_pair("client_id", feishu.app_id.as_str())
        .append_pair(
            "redirect_uri",
            redirect_uri(callback, EnterpriseProvider::Feishu).as_str(),
        )
        .append_pair("response_type", "code")
        .append_pair("scope", "auth:user.id:read")
        .append_pair("state", &encode_state(state));
    url
}

/// Encodes the 256-bit single-use state as canonical unpadded Base64URL.
fn encode_state(state: &OAuthState) -> String {
    data_encoding::BASE64URL_NOPAD.encode(state.as_bytes())
}

/// A bounded provider secret document already parsed from its file.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ProviderSecretDocument(String);

fn load_secret_document(path: &Path) -> Result<ProviderSecretDocument, ProviderError> {
    let file = File::open(path).map_err(|source| ProviderError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    SystemSecretFilePolicy
        .validate_existing(path, &file)
        .map_err(|error| map_secret_policy_error(path, error))?;
    let metadata = file.metadata().map_err(|source| ProviderError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > MAX_PROVIDER_SECRET_BYTES {
        return Err(ProviderError::TooLarge(path.to_path_buf()));
    }
    load_secret_document_from(file, metadata.len(), path)
}

fn load_secret_document_from(
    reader: impl Read,
    reported_len: u64,
    path: &Path,
) -> Result<ProviderSecretDocument, ProviderError> {
    let mut bytes = Vec::with_capacity(reported_len as usize);
    if let Err(source) = reader
        .take(MAX_PROVIDER_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        bytes.zeroize();
        return Err(ProviderError::Read {
            path: path.to_path_buf(),
            source,
        });
    }
    if bytes.len() as u64 > MAX_PROVIDER_SECRET_BYTES {
        bytes.zeroize();
        return Err(ProviderError::TooLarge(path.to_path_buf()));
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(ProviderError::Encoding(path.to_path_buf()));
        }
    };
    Ok(ProviderSecretDocument(text))
}

fn map_secret_policy_error(path: &Path, error: SecretFileError) -> ProviderError {
    match error {
        SecretFileError::Insecure => ProviderError::Insecure(path.to_path_buf()),
        SecretFileError::Platform(source) => ProviderError::Read {
            path: path.to_path_buf(),
            source,
        },
    }
}

fn parse_wecom(
    path: &Path,
    document: ProviderSecretDocument,
) -> Result<WeComCredentials, ProviderError> {
    #[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
    #[serde(deny_unknown_fields)]
    struct WeComDocument {
        corp_id: String,
        agent_id: i64,
        app_secret: String,
    }
    let mut parsed: WeComDocument = parse_document(path, document)?;
    if !(1..=i64::from(u32::MAX)).contains(&parsed.agent_id) {
        return Err(ProviderError::InvalidCredential(ProviderField::AgentId));
    }
    let corp_id = SecretText::new(std::mem::take(&mut parsed.corp_id), ProviderField::CorpId)?;
    let app_secret = SecretText::new(
        std::mem::take(&mut parsed.app_secret),
        ProviderField::AppSecret,
    )?;
    Ok(WeComCredentials {
        corp_id,
        agent_id: parsed.agent_id as u32,
        app_secret,
    })
}

fn parse_feishu(
    path: &Path,
    document: ProviderSecretDocument,
) -> Result<FeishuCredentials, ProviderError> {
    #[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
    #[serde(deny_unknown_fields)]
    struct FeishuDocument {
        app_id: String,
        app_secret: String,
        tenant_key: String,
    }
    let mut parsed: FeishuDocument = parse_document(path, document)?;
    let app_id = SecretText::new(std::mem::take(&mut parsed.app_id), ProviderField::AppId)?;
    let app_secret = SecretText::new(
        std::mem::take(&mut parsed.app_secret),
        ProviderField::AppSecret,
    )?;
    let tenant_key = SecretText::new(
        std::mem::take(&mut parsed.tenant_key),
        ProviderField::TenantKey,
    )?;
    Ok(FeishuCredentials {
        app_id,
        app_secret,
        tenant_key,
    })
}

fn parse_document<T>(path: &Path, document: ProviderSecretDocument) -> Result<T, ProviderError>
where
    T: serde::de::DeserializeOwned,
{
    config::Config::builder()
        .add_source(config::File::from_str(&document.0, FileFormat::Toml))
        .build()
        .and_then(|value| value.try_deserialize())
        .map_err(|_| ProviderError::Schema {
            path: path.to_path_buf(),
        })
}

/// Credential document fields reported by validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderField {
    CorpId,
    AgentId,
    AppId,
    AppSecret,
    TenantKey,
    AccessToken,
}

/// Provider credential loading and authorization URL failures.
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("the enterprise provider secret file is unreadable {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the enterprise provider secret file is too large: {0}")]
    TooLarge(PathBuf),
    #[error("the enterprise provider secret file is not UTF-8: {0}")]
    Encoding(PathBuf),
    #[error("the enterprise provider secret file permits untrusted access: {0}")]
    Insecure(PathBuf),
    #[error("the enterprise provider secret file has an invalid schema: {path}")]
    Schema { path: PathBuf },
    #[error("the enterprise provider credential field is invalid: {0:?}")]
    InvalidCredential(ProviderField),
    #[error("an enabled enterprise provider has no secret file path: {0}")]
    MissingSecretPath(EnterpriseProvider),
    #[error("no enterprise provider credentials were loaded")]
    NoCredentials,
    #[error("the enterprise provider is not configured: {0}")]
    NotConfigured(EnterpriseProvider),
    #[error("the provider authorization URL exceeds the wire bound")]
    AuthorizationUrl,
    #[error("the provider authorization URL could not be built: {0}")]
    Url(#[from] url::ParseError),
    #[error("the provider state could not be bound: {0}")]
    State(#[from] TransitionError),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        FeishuCredentials, MAX_APP_SECRET_BYTES, MAX_CREDENTIAL_ID_BYTES,
        MAX_PROVIDER_SECRET_BYTES, MAX_PROVIDER_TOKEN_TTL, ProviderCredentials, ProviderError,
        ProviderField, ProviderTokenCache, SecretText, WeComCredentials, callback_path,
        encode_state, load_secret_document_from, map_secret_policy_error, redirect_uri,
    };
    use crate::enterprise::CallbackExternalUrl;
    use crate::session::OAuthState;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use url::Url;
    use yonder_core::{EnterpriseProvider, EnterpriseProviders, OsSecureRandom};
    use zeroize::Zeroize;

    fn callback_url() -> CallbackExternalUrl {
        CallbackExternalUrl::new(Url::parse("https://relay.example.test").unwrap()).unwrap()
    }

    fn state() -> OAuthState {
        OAuthState::generate(&mut OsSecureRandom).unwrap()
    }

    fn write_secret_bytes(directory: &std::path::Path, name: &str, contents: &[u8]) -> PathBuf {
        crate::secret_file::secure_test_directory(directory);
        let path = directory.join(name);
        fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            use crate::secret_file::{SecretFilePolicy as _, SystemSecretFilePolicy};
            let file = fs::File::open(&path).unwrap();
            SystemSecretFilePolicy.protect_new(&path, &file).unwrap();
        }
        path
    }

    fn write_secret(directory: &std::path::Path, name: &str, contents: &str) -> PathBuf {
        write_secret_bytes(directory, name, contents.as_bytes())
    }

    fn config_with(
        wecom_secret: Option<PathBuf>,
        feishu_secret: Option<PathBuf>,
    ) -> crate::enterprise::EnterpriseAuthConfig {
        use crate::enterprise::{EnterpriseAuthConfig, ProviderSecrets};
        let providers =
            EnterpriseProviders::new(wecom_secret.is_some(), feishu_secret.is_some()).unwrap();
        let secrets = ProviderSecrets::new(providers, wecom_secret, feishu_secret).unwrap();
        EnterpriseAuthConfig::new(
            "127.0.0.1:8443".parse().unwrap(),
            callback_url(),
            vec![yonder_core::SecretDocument::new(vec![1])],
            yonder_core::SecretDocument::new(vec![2]),
            providers,
            secrets,
        )
        .unwrap()
    }

    #[test]
    fn secret_texts_are_bounded_and_whitespace_free() {
        assert!(SecretText::new("abc".into(), ProviderField::CorpId).is_ok());
        assert!(matches!(
            SecretText::new(String::new(), ProviderField::CorpId),
            Err(ProviderError::InvalidCredential(ProviderField::CorpId))
        ));
        assert!(matches!(
            SecretText::new("a b".into(), ProviderField::CorpId),
            Err(ProviderError::InvalidCredential(ProviderField::CorpId))
        ));
        assert!(matches!(
            SecretText::new(
                "x".repeat(MAX_CREDENTIAL_ID_BYTES + 1),
                ProviderField::CorpId
            ),
            Err(ProviderError::InvalidCredential(ProviderField::CorpId))
        ));
        assert!(
            SecretText::new("x".repeat(MAX_APP_SECRET_BYTES), ProviderField::AppSecret).is_ok()
        );
        assert!(matches!(
            SecretText::new(
                "x".repeat(MAX_APP_SECRET_BYTES + 1),
                ProviderField::AppSecret
            ),
            Err(ProviderError::InvalidCredential(ProviderField::AppSecret))
        ));
    }

    #[test]
    fn secret_loading_validates_documents_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let wecom = write_secret(
            directory.path(),
            "wecom.secret",
            "corp_id = \"ww1234567890abcdef\"\nagent_id = 1000002\napp_secret = \"s3cret\"\n",
        );
        let credentials = ProviderCredentials::load(&config_with(Some(wecom), None)).unwrap();
        assert_eq!(credentials.providers().unwrap().len(), 1);
        let url = credentials
            .authorization_url(EnterpriseProvider::WeCom, &callback_url(), &state())
            .unwrap();
        assert!(
            url.as_str()
                .starts_with("https://login.work.weixin.qq.com/wwlogin/sso/login")
        );

        let malformed = write_secret(directory.path(), "bad.secret", "corp_id = 42\n");
        let error = ProviderCredentials::load(&config_with(Some(malformed), None)).unwrap_err();
        assert!(matches!(error, ProviderError::Schema { .. }));

        let unknown = write_secret(
            directory.path(),
            "unknown.secret",
            "corp_id = \"x\"\nagent_id = 1\napp_secret = \"y\"\nunknown = true\n",
        );
        assert!(matches!(
            ProviderCredentials::load(&config_with(Some(unknown), None)),
            Err(ProviderError::Schema { .. })
        ));

        let oversized = write_secret(
            directory.path(),
            "oversized.secret",
            &format!(
                "corp_id = \"{}\"\n",
                "x".repeat(MAX_PROVIDER_SECRET_BYTES as usize)
            ),
        );
        assert!(matches!(
            ProviderCredentials::load(&config_with(Some(oversized), None)),
            Err(ProviderError::TooLarge(_))
        ));

        let invalid_utf8 = write_secret_bytes(directory.path(), "invalid-utf8.secret", &[0xff]);
        assert!(matches!(
            ProviderCredentials::load(&config_with(Some(invalid_utf8), None)),
            Err(ProviderError::Encoding(_))
        ));
    }

    #[test]
    fn secret_document_read_is_bounded_against_growth_and_io_failure() {
        use std::io::{self, Cursor, Read};

        let path = std::path::Path::new("provider.secret");
        let exact = vec![b'x'; MAX_PROVIDER_SECRET_BYTES as usize];
        assert_eq!(
            load_secret_document_from(Cursor::new(exact), MAX_PROVIDER_SECRET_BYTES, path)
                .unwrap()
                .0
                .len(),
            MAX_PROVIDER_SECRET_BYTES as usize
        );

        let grew_after_metadata = vec![b'x'; MAX_PROVIDER_SECRET_BYTES as usize + 1];
        assert!(matches!(
            load_secret_document_from(Cursor::new(grew_after_metadata), 1, path),
            Err(ProviderError::TooLarge(actual)) if actual == path
        ));
        assert!(matches!(
            load_secret_document_from(FailingReader, 0, path),
            Err(ProviderError::Read { source, .. }) if source.kind() == io::ErrorKind::Other
        ));

        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("provider secret read failed"))
            }
        }
    }

    #[test]
    fn both_providers_load_together_and_build_their_urls() {
        let directory = tempfile::tempdir().unwrap();
        let wecom = write_secret(
            directory.path(),
            "wecom.secret",
            "corp_id = \"ww1234567890abcdef\"\nagent_id = 7\napp_secret = \"s3cret\"\n",
        );
        let feishu = write_secret(
            directory.path(),
            "feishu.secret",
            "app_id = \"cli_abc123\"\napp_secret = \"s3cret\"\ntenant_key = \"tenant-abc\"\n",
        );
        let credentials =
            ProviderCredentials::load(&config_with(Some(wecom), Some(feishu))).unwrap();
        assert_eq!(
            credentials.providers().unwrap(),
            EnterpriseProviders::new(true, true).unwrap()
        );
        let state = state();
        let wecom_url = credentials
            .authorization_url(EnterpriseProvider::WeCom, &callback_url(), &state)
            .unwrap();
        assert!(wecom_url.as_str().contains("appid=ww1234567890abcdef"));
        assert!(wecom_url.as_str().contains("login_type=CorpApp"));
        assert!(wecom_url.as_str().contains("agentid=7"));
        assert!(wecom_url.as_str().contains(&encode_state(&state)));
        assert!(!wecom_url.as_str().contains('#'));

        let feishu_url = credentials
            .authorization_url(EnterpriseProvider::Feishu, &callback_url(), &state)
            .unwrap();
        assert!(
            feishu_url
                .as_str()
                .starts_with("https://accounts.feishu.cn/open-apis/authen/v1/authorize")
        );
        assert!(feishu_url.as_str().contains("client_id=cli_abc123"));
        assert!(feishu_url.as_str().contains("response_type=code"));
        assert!(feishu_url.as_str().contains("scope=auth%3Auser.id%3Aread"));
        assert!(feishu_url.as_str().contains(&encode_state(&state)));
        assert!(!feishu_url.as_str().contains('#'));

        // The same state and credentials always build the same URL.
        let wecom_built_again = credentials
            .authorization_url(EnterpriseProvider::WeCom, &callback_url(), &state)
            .unwrap();
        assert_eq!(wecom_built_again, wecom_url);
    }

    #[test]
    fn disabled_providers_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let wecom = write_secret(
            directory.path(),
            "wecom.secret",
            "corp_id = \"ww1234567890abcdef\"\nagent_id = 7\napp_secret = \"s3cret\"\n",
        );
        let credentials = ProviderCredentials::load(&config_with(Some(wecom), None)).unwrap();
        let error = credentials
            .authorization_url(EnterpriseProvider::Feishu, &callback_url(), &state())
            .unwrap_err();
        assert!(matches!(
            error,
            ProviderError::NotConfigured(EnterpriseProvider::Feishu)
        ));
    }

    #[test]
    fn redirect_uris_use_canonical_callback_paths() {
        let base = callback_url();
        assert_eq!(
            redirect_uri(&base, EnterpriseProvider::WeCom).as_str(),
            "https://relay.example.test/yonder/callback/wecom"
        );
        assert_eq!(
            redirect_uri(&base, EnterpriseProvider::Feishu).as_str(),
            "https://relay.example.test/yonder/callback/feishu"
        );
        assert_eq!(
            callback_path(EnterpriseProvider::WeCom),
            "/yonder/callback/wecom"
        );
        assert_eq!(
            callback_path(EnterpriseProvider::Feishu),
            "/yonder/callback/feishu"
        );
    }

    #[test]
    fn state_encoding_is_canonical_unpadded_base64url() {
        let state = state();
        let encoded = encode_state(&state);
        assert_eq!(encoded.len(), 43);
        assert!(
            encoded.chars().all(
                |character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            )
        );
        assert!(!encoded.contains('='));
        assert_eq!(
            data_encoding::BASE64URL_NOPAD
                .decode(encoded.as_bytes())
                .unwrap(),
            state.as_bytes()
        );
        let mut other = state.clone();
        other.zeroize();
        assert_ne!(
            encoded,
            encode_state(&OAuthState::generate(&mut OsSecureRandom).unwrap())
        );
    }

    #[test]
    fn credentials_zeroize_on_drop() {
        let mut wecom = WeComCredentials {
            corp_id: SecretText::new("ww1234567890abcdef".into(), ProviderField::CorpId).unwrap(),
            agent_id: 7,
            app_secret: SecretText::new("s3cret".into(), ProviderField::AppSecret).unwrap(),
        };
        let mut feishu = FeishuCredentials {
            app_id: SecretText::new("cli_abc123".into(), ProviderField::AppId).unwrap(),
            app_secret: SecretText::new("s3cret".into(), ProviderField::AppSecret).unwrap(),
            tenant_key: SecretText::new("tenant-abc".into(), ProviderField::TenantKey).unwrap(),
        };
        wecom.zeroize();
        feishu.zeroize();
        assert!(wecom.corp_id.as_str().is_empty());
        assert!(wecom.app_secret.as_str().is_empty());
        assert!(feishu.app_id.as_str().is_empty());
        assert!(feishu.app_secret.as_str().is_empty());
        assert!(feishu.tenant_key.as_str().is_empty());
    }

    #[test]
    fn authorization_urls_match_provider_contracts_exactly() {
        let credentials = ProviderCredentials::from_credentials(
            Some(WeComCredentials {
                corp_id: SecretText::new("ww1234567890abcdef".into(), ProviderField::CorpId)
                    .unwrap(),
                agent_id: 7,
                app_secret: SecretText::new("wecom-secret".into(), ProviderField::AppSecret)
                    .unwrap(),
            }),
            Some(FeishuCredentials {
                app_id: SecretText::new("cli_abc123".into(), ProviderField::AppId).unwrap(),
                app_secret: SecretText::new("feishu-secret".into(), ProviderField::AppSecret)
                    .unwrap(),
                tenant_key: SecretText::new("tenant-abc".into(), ProviderField::TenantKey).unwrap(),
            }),
        );
        let state = state();
        let encoded_state = encode_state(&state);
        let wecom = credentials
            .authorization_url(EnterpriseProvider::WeCom, &callback_url(), &state)
            .unwrap();
        let wecom = Url::parse(wecom.as_str()).unwrap();
        assert_eq!(wecom.scheme(), "https");
        assert_eq!(wecom.host_str(), Some("login.work.weixin.qq.com"));
        assert_eq!(wecom.path(), "/wwlogin/sso/login");
        assert_eq!(
            wecom.query_pairs().collect::<Vec<_>>(),
            vec![
                ("login_type".into(), "CorpApp".into()),
                ("appid".into(), "ww1234567890abcdef".into()),
                ("agentid".into(), "7".into()),
                (
                    "redirect_uri".into(),
                    "https://relay.example.test/yonder/callback/wecom".into(),
                ),
                ("state".into(), encoded_state.clone().into()),
            ]
        );

        let feishu = credentials
            .authorization_url(EnterpriseProvider::Feishu, &callback_url(), &state)
            .unwrap();
        let feishu = Url::parse(feishu.as_str()).unwrap();
        assert_eq!(feishu.scheme(), "https");
        assert_eq!(feishu.host_str(), Some("accounts.feishu.cn"));
        assert_eq!(feishu.path(), "/open-apis/authen/v1/authorize");
        assert_eq!(
            feishu.query_pairs().collect::<Vec<_>>(),
            vec![
                ("client_id".into(), "cli_abc123".into()),
                (
                    "redirect_uri".into(),
                    "https://relay.example.test/yonder/callback/feishu".into(),
                ),
                ("response_type".into(), "code".into()),
                ("scope".into(), "auth:user.id:read".into()),
                ("state".into(), encoded_state.into()),
            ]
        );
    }

    #[test]
    fn debug_and_schema_errors_never_disclose_credentials() {
        let canaries = [
            "ww-debug-canary",
            "wecom-secret-canary",
            "cli-debug-canary",
            "feishu-secret-canary",
            "tenant-debug-canary",
        ];
        let credentials = ProviderCredentials::from_credentials(
            Some(WeComCredentials {
                corp_id: SecretText::new(canaries[0].into(), ProviderField::CorpId).unwrap(),
                agent_id: 7,
                app_secret: SecretText::new(canaries[1].into(), ProviderField::AppSecret).unwrap(),
            }),
            Some(FeishuCredentials {
                app_id: SecretText::new(canaries[2].into(), ProviderField::AppId).unwrap(),
                app_secret: SecretText::new(canaries[3].into(), ProviderField::AppSecret).unwrap(),
                tenant_key: SecretText::new(canaries[4].into(), ProviderField::TenantKey).unwrap(),
            }),
        );
        let rendered = format!(
            "{credentials:?} {:?} {:?} {:?}",
            credentials.wecom().unwrap(),
            credentials.feishu().unwrap(),
            credentials.wecom().unwrap().corp_id
        );
        assert!(canaries.iter().all(|canary| !rendered.contains(canary)));
        assert!(rendered.contains("agent_id: 7"));
        assert!(rendered.matches("<redacted>").count() >= 7);

        let directory = tempfile::tempdir().unwrap();
        let schema_canary = "schema-secret-canary";
        let secret = write_secret(
            directory.path(),
            "invalid-feishu.secret",
            &format!(
                "app_id = \"cli\"\napp_secret = \"{schema_canary}\"\ntenant_key = [\"bad\"]\n"
            ),
        );
        let error = ProviderCredentials::load(&config_with(None, Some(secret))).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(schema_canary));
    }

    #[test]
    fn token_cache_is_fixed_early_expiring_and_generation_safe() {
        let now = Instant::now();
        let mut cache = ProviderTokenCache::empty();
        let old = SecretText::new("old-token".into(), ProviderField::AccessToken).unwrap();
        cache
            .store(old.clone(), Duration::from_secs(100), now)
            .unwrap();
        assert_eq!(
            cache.fresh(now + Duration::from_secs(89)),
            Some(old.clone())
        );
        // Ten percent of a short lifetime is reserved as the early-expiry
        // margin, using only monotonic Instants.
        assert!(cache.fresh(now + Duration::from_secs(90)).is_none());

        let new = SecretText::new("new-token".into(), ProviderField::AccessToken).unwrap();
        cache
            .store(new.clone(), Duration::from_secs(100), now)
            .unwrap();
        cache.invalidate_if(&old);
        assert_eq!(cache.fresh(now), Some(new.clone()));
        cache.invalidate_if(&new);
        assert!(cache.fresh(now).is_none());

        assert!(
            cache
                .store(
                    SecretText::new("zero".into(), ProviderField::AccessToken).unwrap(),
                    Duration::ZERO,
                    now,
                )
                .is_err()
        );
        assert!(
            cache
                .store(
                    SecretText::new("long".into(), ProviderField::AccessToken).unwrap(),
                    MAX_PROVIDER_TOKEN_TTL + Duration::from_secs(1),
                    now,
                )
                .is_err()
        );
    }

    #[test]
    fn wecom_agent_ids_are_bounded_to_the_documented_range() {
        let directory = tempfile::tempdir().unwrap();
        for agent_id in ["0", "-1", "4294967296"] {
            let secret = write_secret(
                directory.path(),
                &format!("wecom-{agent_id}.secret"),
                &format!(
                    "corp_id = \"ww1234567890abcdef\"\nagent_id = {agent_id}\napp_secret = \"s3cret\"\n"
                ),
            );
            assert!(matches!(
                ProviderCredentials::load(&config_with(Some(secret), None)),
                Err(ProviderError::InvalidCredential(ProviderField::AgentId))
            ));
        }
    }

    #[test]
    fn feishu_secret_fields_are_validated_independently() {
        let directory = tempfile::tempdir().unwrap();
        for (name, document, field) in [
            (
                "invalid-app-secret.secret",
                "app_id = \"cli_abc123\"\napp_secret = \"bad secret\"\ntenant_key = \"tenant-abc\"\n",
                ProviderField::AppSecret,
            ),
            (
                "invalid-tenant.secret",
                "app_id = \"cli_abc123\"\napp_secret = \"s3cret\"\ntenant_key = \"\"\n",
                ProviderField::TenantKey,
            ),
        ] {
            let secret = write_secret(directory.path(), name, document);
            assert!(matches!(
                ProviderCredentials::load(&config_with(None, Some(secret))),
                Err(ProviderError::InvalidCredential(actual)) if actual == field
            ));
        }
    }

    #[test]
    fn secret_policy_failures_map_to_provider_errors() {
        // The mapping is a pure fail-closed boundary: every policy failure
        // becomes the matching provider error.
        let path = std::path::Path::new("wecom.secret");
        assert!(matches!(
            map_secret_policy_error(
                path,
                crate::secret_file::SecretFileError::Insecure
            ),
            ProviderError::Insecure(mapped) if mapped == path
        ));
        assert!(matches!(
            map_secret_policy_error(
                path,
                crate::secret_file::SecretFileError::Platform(std::io::Error::other("platform"))
            ),
            ProviderError::Read { source, .. } if source.kind() == std::io::ErrorKind::Other
        ));
    }

    #[cfg(unix)]
    #[test]
    fn untrusted_secret_files_fail_closed_at_load() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("wecom.secret");
        fs::write(
            &secret,
            "corp_id = \"ww1234567890abcdef\"\nagent_id = 7\napp_secret = \"s3cret\"\n",
        )
        .unwrap();
        // The secret file keeps the default group-readable mode: the
        // policy rejects it and the load fails closed.
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ProviderCredentials::load(&config_with(Some(secret), None)),
            Err(ProviderError::Insecure(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn untrusted_secret_files_fail_closed_at_load() {
        use crate::secret_file::{SecretFilePolicy as _, SystemSecretFilePolicy};
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("wecom.secret");
        fs::write(
            &secret,
            "corp_id = \"ww1234567890abcdef\"\nagent_id = 7\napp_secret = \"s3cret\"\n",
        )
        .unwrap();
        crate::secret_file::secure_test_directory(directory.path());
        let file = fs::File::open(&secret).unwrap();
        SystemSecretFilePolicy.protect_new(&secret, &file).unwrap();
        // Re-enable ACL inheritance: the protected DACL is lost and the
        // policy rejects the file at load.
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let status =
            Command::new(std::path::PathBuf::from(system_root).join("System32/icacls.exe"))
                .arg(&secret)
                .arg("/inheritance:e")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
        assert!(status.success());
        assert!(matches!(
            ProviderCredentials::load(&config_with(Some(secret), None)),
            Err(ProviderError::Insecure(_))
        ));
    }
}
