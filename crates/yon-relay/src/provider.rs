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
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;
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

/// The WeCom (企业微信) self-built application credentials.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct WeComCredentials {
    /// The enterprise corporate identifier.
    pub(crate) corp_id: SecretText,
    /// The self-built application agent identifier.
    pub(crate) agent_id: u32,
    /// The self-built application secret.
    pub(crate) app_secret: SecretText,
}

/// The Feishu (飞书) enterprise self-built application credentials.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct FeishuCredentials {
    /// The application identifier.
    pub(crate) app_id: SecretText,
    /// The application secret.
    pub(crate) app_secret: SecretText,
}

/// A zeroizing credential text.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretText(String);

impl SecretText {
    pub(crate) fn new(value: String, kind: ProviderField) -> Result<Self, ProviderError> {
        let bound = match kind {
            ProviderField::CorpId | ProviderField::AppId => MAX_CREDENTIAL_ID_BYTES,
            ProviderField::AgentId | ProviderField::AppSecret => MAX_APP_SECRET_BYTES,
        };
        if value.is_empty() || value.len() > bound || value.chars().any(char::is_whitespace) {
            return Err(ProviderError::InvalidCredential(kind));
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The credentials of every enabled provider, loaded once at startup.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ProviderCredentials {
    wecom: Option<WeComCredentials>,
    feishu: Option<FeishuCredentials>,
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
        Ok(Self { wecom, feishu })
    }

    /// The WeCom credentials when WeCom is configured.
    pub(crate) const fn wecom(&self) -> Option<&WeComCredentials> {
        self.wecom.as_ref()
    }

    /// The Feishu credentials when Feishu is configured.
    pub(crate) const fn feishu(&self) -> Option<&FeishuCredentials> {
        self.feishu.as_ref()
    }

    /// Constructs credentials directly for crate-internal tests.
    #[cfg(test)]
    pub(crate) fn from_credentials(
        wecom: Option<WeComCredentials>,
        feishu: Option<FeishuCredentials>,
    ) -> Self {
        Self { wecom, feishu }
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
    let mut url = Url::parse("https://open.weixin.qq.com/connect/oauth2/authorize")
        .expect("fixed wecom authorize endpoint");
    url.query_pairs_mut()
        .append_pair("appid", wecom.corp_id.as_str())
        .append_pair("agentid", &wecom.agent_id.to_string())
        .append_pair(
            "redirect_uri",
            redirect_uri(callback, EnterpriseProvider::WeCom).as_str(),
        )
        .append_pair("response_type", "code")
        .append_pair("scope", "snsapi_base")
        .append_pair("state", &encode_state(state));
    url.set_fragment(Some("wechat_redirect"));
    url
}

fn feishu_authorization_url(
    feishu: &FeishuCredentials,
    callback: &CallbackExternalUrl,
    state: &OAuthState,
) -> Url {
    let mut url = Url::parse("https://open.feishu.cn/open-apis/authen/v1/authorize")
        .expect("fixed feishu authorize endpoint");
    url.query_pairs_mut()
        .append_pair("app_id", feishu.app_id.as_str())
        .append_pair(
            "redirect_uri",
            redirect_uri(callback, EnterpriseProvider::Feishu).as_str(),
        )
        .append_pair("scope", "authen:user.id:read")
        .append_pair("state", &encode_state(state));
    url
}

/// Encodes the single-use state as lowercase hexadecimal for the wire.
fn encode_state(state: &OAuthState) -> String {
    data_encoding::HEXLOWER.encode(state.as_bytes())
}

/// A bounded provider secret document already parsed from its file.
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
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PROVIDER_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ProviderError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_PROVIDER_SECRET_BYTES {
        return Err(ProviderError::TooLarge(path.to_path_buf()));
    }
    let text = String::from_utf8(bytes).map_err(|_| ProviderError::Encoding(path.to_path_buf()))?;
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
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WeComDocument {
        corp_id: String,
        agent_id: i64,
        app_secret: String,
    }
    let parsed: WeComDocument = parse_document(path, document)?;
    if !(1..=i64::from(u32::MAX)).contains(&parsed.agent_id) {
        return Err(ProviderError::InvalidCredential(ProviderField::AgentId));
    }
    let corp_id = SecretText::new(parsed.corp_id, ProviderField::CorpId)?;
    let app_secret = SecretText::new(parsed.app_secret, ProviderField::AppSecret)?;
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
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FeishuDocument {
        app_id: String,
        app_secret: String,
    }
    let parsed: FeishuDocument = parse_document(path, document)?;
    let app_id = SecretText::new(parsed.app_id, ProviderField::AppId)?;
    let app_secret = SecretText::new(parsed.app_secret, ProviderField::AppSecret)?;
    Ok(FeishuCredentials { app_id, app_secret })
}

fn parse_document<T>(path: &Path, document: ProviderSecretDocument) -> Result<T, ProviderError>
where
    T: serde::de::DeserializeOwned,
{
    config::Config::builder()
        .add_source(config::File::from_str(&document.0, FileFormat::Toml))
        .build()
        .and_then(|value| value.try_deserialize())
        .map_err(|error| ProviderError::Schema {
            path: path.to_path_buf(),
            source: Box::new(error),
        })
}

/// Credential document fields reported by validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderField {
    CorpId,
    AgentId,
    AppId,
    AppSecret,
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
    #[error("the enterprise provider secret file is invalid {path}: {source}")]
    Schema {
        path: PathBuf,
        #[source]
        source: Box<config::ConfigError>,
    },
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
        MAX_PROVIDER_SECRET_BYTES, ProviderCredentials, ProviderError, ProviderField, SecretText,
        WeComCredentials, callback_path, encode_state, redirect_uri,
    };
    use crate::enterprise::CallbackExternalUrl;
    use crate::session::OAuthState;
    use std::fs;
    use std::path::PathBuf;
    use url::Url;
    use yonder_core::{EnterpriseProvider, EnterpriseProviders, OsSecureRandom};
    use zeroize::Zeroize;

    fn callback_url() -> CallbackExternalUrl {
        CallbackExternalUrl::new(Url::parse("https://relay.example.test").unwrap()).unwrap()
    }

    fn state() -> OAuthState {
        OAuthState::generate(&mut OsSecureRandom).unwrap()
    }

    fn write_secret(directory: &std::path::Path, name: &str, contents: &str) -> PathBuf {
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
                .starts_with("https://open.weixin.qq.com/connect/oauth2/authorize")
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
            "app_id = \"cli_abc123\"\napp_secret = \"s3cret\"\n",
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
        assert!(wecom_url.as_str().contains("agentid=7"));
        assert!(wecom_url.as_str().contains(&encode_state(&state)));
        assert!(wecom_url.as_str().ends_with("#wechat_redirect"));

        let feishu_url = credentials
            .authorization_url(EnterpriseProvider::Feishu, &callback_url(), &state)
            .unwrap();
        assert!(
            feishu_url
                .as_str()
                .starts_with("https://open.feishu.cn/open-apis/authen/v1/authorize")
        );
        assert!(feishu_url.as_str().contains("app_id=cli_abc123"));
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
    fn state_encoding_is_fixed_length_lowercase_hex() {
        let state = state();
        let encoded = encode_state(&state);
        assert_eq!(encoded.len(), 64);
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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
        };
        wecom.zeroize();
        feishu.zeroize();
        assert!(wecom.corp_id.as_str().is_empty());
        assert!(wecom.app_secret.as_str().is_empty());
        assert!(feishu.app_id.as_str().is_empty());
        assert!(feishu.app_secret.as_str().is_empty());
    }
}
