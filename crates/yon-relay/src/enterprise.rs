use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;
use url::Url;
use yonder_core::{EnterpriseProvider, EnterpriseProviders, SecretDocument};

/// Fully validated enterprise-mode configuration.
///
/// Its presence switches the relay from normal mode to enterprise mode;
/// the two modes are mutually exclusive and immutable for the process
/// lifetime because configuration is loaded exactly once at startup.
#[derive(Debug)]
pub struct EnterpriseAuthConfig {
    listen: SocketAddr,
    callback_url: CallbackExternalUrl,
    certificate_chain: Vec<SecretDocument>,
    private_key: SecretDocument,
    providers: EnterpriseProviders,
    secrets: ProviderSecrets,
}

impl EnterpriseAuthConfig {
    /// Validates cross-field invariants of an enterprise-mode configuration.
    pub fn new(
        listen: SocketAddr,
        callback_url: CallbackExternalUrl,
        certificate_chain: Vec<SecretDocument>,
        private_key: SecretDocument,
        providers: EnterpriseProviders,
        secrets: ProviderSecrets,
    ) -> Result<Self, EnterpriseConfigError> {
        if certificate_chain.is_empty() {
            return Err(EnterpriseConfigError::EmptyCertificateChain);
        }
        Ok(Self {
            listen,
            callback_url,
            certificate_chain,
            private_key,
            providers,
            secrets,
        })
    }

    /// The HTTPS callback listener address.
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The externally reachable HTTPS base URL used for OAuth redirects.
    #[must_use]
    pub fn callback_url(&self) -> &Url {
        self.callback_url.as_url()
    }

    /// The validated external callback origin, used to build redirect URIs.
    #[must_use]
    pub const fn callback_external(&self) -> &CallbackExternalUrl {
        &self.callback_url
    }

    /// The callback certificate chain documents.
    #[must_use]
    pub fn certificate_chain(&self) -> &[SecretDocument] {
        &self.certificate_chain
    }

    /// The callback private key document.
    #[must_use]
    pub fn private_key(&self) -> &SecretDocument {
        &self.private_key
    }

    /// The configured enterprise providers.
    #[must_use]
    pub const fn providers(&self) -> EnterpriseProviders {
        self.providers
    }

    /// The sensitive credential file path of one provider.
    #[must_use]
    pub fn secret_path(&self, provider: EnterpriseProvider) -> Option<&Path> {
        self.secrets.path(provider)
    }
}

/// A validated external HTTPS callback base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackExternalUrl(Url);

impl CallbackExternalUrl {
    /// Validates that the callback base URL is a bare HTTPS origin with a
    /// public host.
    ///
    /// A bare origin keeps OAuth redirect construction and the operator's
    /// reverse-proxy expectations verifiable: no path, query or fragment.
    /// The host must be a dotted domain or an IP literal because the
    /// provider's servers must be able to reach the callback; the `url`
    /// crate normalizes inputs like `https:///path` into a single-label
    /// host, which is rejected here.
    pub fn new(url: Url) -> Result<Self, EnterpriseConfigError> {
        if url.scheme() != "https" {
            return Err(EnterpriseConfigError::CallbackUrlScheme);
        }
        let public_host = match url.host() {
            Some(url::Host::Domain(host)) => !host.is_empty() && host.contains('.'),
            Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => true,
            None => false,
        };
        if !public_host {
            return Err(EnterpriseConfigError::CallbackUrlHost);
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(EnterpriseConfigError::CallbackUrlPath);
        }
        Ok(Self(url))
    }

    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

/// Resolved secret file paths of the enabled providers.
///
/// Every enabled provider must own exactly one secret file; a path for a
/// disabled provider is rejected so configuration stays fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSecrets {
    wecom: Option<PathBuf>,
    feishu: Option<PathBuf>,
}

impl ProviderSecrets {
    /// Checks the provider/path correspondence against the enabled set.
    pub fn new(
        providers: EnterpriseProviders,
        wecom: Option<PathBuf>,
        feishu: Option<PathBuf>,
    ) -> Result<Self, EnterpriseConfigError> {
        if providers.contains(EnterpriseProvider::WeCom) && wecom.is_none() {
            return Err(EnterpriseConfigError::MissingProviderSecret);
        }
        if providers.contains(EnterpriseProvider::Feishu) && feishu.is_none() {
            return Err(EnterpriseConfigError::MissingProviderSecret);
        }
        if !providers.contains(EnterpriseProvider::WeCom) && wecom.is_some() {
            return Err(EnterpriseConfigError::UnexpectedProviderSecret);
        }
        if !providers.contains(EnterpriseProvider::Feishu) && feishu.is_some() {
            return Err(EnterpriseConfigError::UnexpectedProviderSecret);
        }
        Ok(Self { wecom, feishu })
    }

    #[must_use]
    pub fn path(&self, provider: EnterpriseProvider) -> Option<&Path> {
        match provider {
            EnterpriseProvider::WeCom => self.wecom.as_deref(),
            EnterpriseProvider::Feishu => self.feishu.as_deref(),
        }
    }
}

/// Enterprise-mode configuration validation failures.
#[derive(Debug, Error)]
pub enum EnterpriseConfigError {
    #[error("enterprise mode requires at least one authentication provider")]
    NoProvider,
    #[error("enterprise mode requires the callback certificate and private key")]
    MissingCallbackTls,
    #[error("enterprise mode requires the callback listen address")]
    MissingCallbackListen,
    #[error("enterprise mode requires the callback external URL")]
    MissingCallbackUrl,
    #[error("the enterprise callback certificate chain is empty")]
    EmptyCertificateChain,
    #[error("the enterprise callback URL is invalid: {0}")]
    CallbackUrl(#[from] url::ParseError),
    #[error("the enterprise callback URL must use the https scheme")]
    CallbackUrlScheme,
    #[error("the enterprise callback URL must use a dotted domain or IP address host")]
    CallbackUrlHost,
    #[error(
        "the enterprise callback URL must be a bare https origin without path, query or fragment"
    )]
    CallbackUrlPath,
    #[error("the enterprise callback listen address is invalid: {0}")]
    CallbackListen(#[source] std::net::AddrParseError),
    #[error("an enabled enterprise provider is missing its secret file")]
    MissingProviderSecret,
    #[error("an enterprise provider secret file is configured for a disabled provider")]
    UnexpectedProviderSecret,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CallbackExternalUrl, EnterpriseAuthConfig, EnterpriseConfigError, ProviderSecrets,
    };
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use url::Url;
    use yonder_core::{EnterpriseProvider, EnterpriseProviders, SecretDocument};

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    fn config(
        wecom: bool,
        feishu: bool,
        wecom_secret: Option<PathBuf>,
        feishu_secret: Option<PathBuf>,
    ) -> Result<EnterpriseAuthConfig, EnterpriseConfigError> {
        let providers = EnterpriseProviders::new(wecom, feishu)
            .map_err(|_| EnterpriseConfigError::NoProvider)?;
        let secrets = ProviderSecrets::new(providers, wecom_secret, feishu_secret)?;
        EnterpriseAuthConfig::new(
            "127.0.0.1:8443".parse::<SocketAddr>().unwrap(),
            CallbackExternalUrl::new(url("https://relay.example.test")).unwrap(),
            vec![SecretDocument::new(vec![1, 2, 3])],
            SecretDocument::new(vec![4, 5, 6]),
            providers,
            secrets,
        )
    }

    #[test]
    fn callback_urls_require_bare_https_origin() {
        assert!(CallbackExternalUrl::new(url("https://relay.example.test")).is_ok());
        assert!(CallbackExternalUrl::new(url("https://relay.example.test/")).is_ok());
        assert!(CallbackExternalUrl::new(url("http://relay.example.test")).is_err());
        assert!(CallbackExternalUrl::new(url("https:///path")).is_err());
        assert!(CallbackExternalUrl::new(url("https://relay.example.test/cb")).is_err());
        assert!(CallbackExternalUrl::new(url("https://relay.example.test?x=1")).is_err());
        assert!(CallbackExternalUrl::new(url("https://relay.example.test#f")).is_err());
        // IP-literal hosts are public callback targets too.
        assert!(CallbackExternalUrl::new(url("https://127.0.0.1")).is_ok());
        assert!(CallbackExternalUrl::new(url("https://[::1]")).is_ok());
        // `https://` is rejected at parse time with a structured error.
        assert!(matches!(
            Url::parse("https://"),
            Err(url::ParseError::EmptyHost)
        ));
    }

    #[test]
    fn config_accessors_expose_every_validated_part() {
        let listen: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let callback = CallbackExternalUrl::new(url("https://relay.example.test")).unwrap();
        let providers = EnterpriseProviders::new(true, true).unwrap();
        let secrets = ProviderSecrets::new(
            providers,
            Some(PathBuf::from("wecom.secret")),
            Some(PathBuf::from("feishu.secret")),
        )
        .unwrap();
        let config = EnterpriseAuthConfig::new(
            listen,
            callback.clone(),
            vec![SecretDocument::new(vec![1, 2, 3])],
            SecretDocument::new(vec![4, 5, 6]),
            providers,
            secrets,
        )
        .unwrap();
        assert_eq!(config.listen(), listen);
        assert_eq!(config.callback_url(), callback.as_url());
        assert_eq!(config.callback_external(), &callback);
        assert_eq!(config.certificate_chain().len(), 1);
        assert_eq!(config.certificate_chain()[0].as_bytes(), &[1, 2, 3]);
        assert_eq!(config.private_key().as_bytes(), &[4, 5, 6]);
        assert_eq!(config.providers(), providers);
        assert_eq!(
            config.secret_path(EnterpriseProvider::WeCom),
            Some(Path::new("wecom.secret"))
        );
    }

    #[test]
    fn every_enabled_provider_needs_its_secret_file() {
        assert!(matches!(
            config(true, false, None, None),
            Err(EnterpriseConfigError::MissingProviderSecret)
        ));
        assert!(matches!(
            config(false, true, None, None),
            Err(EnterpriseConfigError::MissingProviderSecret)
        ));
        assert!(config(true, false, Some(PathBuf::from("wecom.secret")), None).is_ok());
        assert!(config(false, true, None, Some(PathBuf::from("feishu.secret"))).is_ok());
    }

    #[test]
    fn secret_files_for_disabled_providers_are_rejected() {
        assert!(matches!(
            config(
                true,
                false,
                Some(PathBuf::from("wecom.secret")),
                Some(PathBuf::from("feishu.secret"))
            ),
            Err(EnterpriseConfigError::UnexpectedProviderSecret)
        ));
        assert!(matches!(
            config(
                false,
                true,
                Some(PathBuf::from("wecom.secret")),
                Some(PathBuf::from("feishu.secret"))
            ),
            Err(EnterpriseConfigError::UnexpectedProviderSecret)
        ));
        assert!(matches!(
            config(false, false, None, None),
            Err(EnterpriseConfigError::NoProvider)
        ));
    }

    #[test]
    fn both_providers_may_share_one_configuration() {
        let config = config(
            true,
            true,
            Some(PathBuf::from("wecom.secret")),
            Some(PathBuf::from("feishu.secret")),
        )
        .unwrap();
        assert_eq!(config.providers().len(), 2);
        assert_eq!(
            config.secret_path(EnterpriseProvider::WeCom),
            Some(Path::new("wecom.secret"))
        );
        assert_eq!(
            config.secret_path(EnterpriseProvider::Feishu),
            Some(Path::new("feishu.secret"))
        );
    }

    #[test]
    fn empty_certificate_chain_is_rejected() {
        let providers = EnterpriseProviders::new(true, false).unwrap();
        let secrets =
            ProviderSecrets::new(providers, Some(PathBuf::from("wecom.secret")), None).unwrap();
        let error = EnterpriseAuthConfig::new(
            "127.0.0.1:8443".parse::<SocketAddr>().unwrap(),
            CallbackExternalUrl::new(url("https://relay.example.test")).unwrap(),
            Vec::new(),
            SecretDocument::new(vec![4, 5, 6]),
            providers,
            secrets,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            EnterpriseConfigError::EmptyCertificateChain
        ));
    }
}
