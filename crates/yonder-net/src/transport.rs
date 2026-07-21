use crate::RelayExternalAddress;
use crate::error::NetworkBuildError;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::{Transport, upgrade};
use libp2p::identity::Keypair;
use libp2p::{PeerId, dns, noise, quic, relay, tcp, websocket, yamux};
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer,
    pem::{SectionKind, SliceIter},
};
use std::time::Duration;
use yonder_core::{IdentitySeed, SecretDocument, SecureRandom};

/// Maximum setup time for one transport dial across every supported stack.
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(8);

/// Maximum number of WSS certificates accepted in a chain or trust set.
pub const WSS_CERTIFICATE_LIMIT: usize = 8;
const MAX_WSS_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_WSS_PRIVATE_KEY_BYTES: usize = 64 * 1024;

/// A leaf-first, bounded WSS certificate chain.
pub struct WssCertificateChain(Vec<Vec<u8>>);

impl WssCertificateChain {
    /// Parses one or more DER certificates or PEM bundles without reimplementing PEM.
    pub fn from_documents(
        documents: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, NetworkBuildError> {
        let certificates = parse_certificate_documents(documents)
            .map_err(|_| NetworkBuildError::InvalidWssCertificateChain)?;
        if certificates.is_empty() {
            return Err(NetworkBuildError::InvalidWssCertificateChain);
        }
        Ok(Self(certificates))
    }

    fn single(certificate_der: Vec<u8>) -> Self {
        Self(vec![certificate_der])
    }

    fn leaf(&self) -> Option<&[u8]> {
        self.0.first().map(Vec::as_slice)
    }

    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(Vec::as_slice)
    }

    fn into_upstream(self) -> impl Iterator<Item = websocket::tls::Certificate> {
        self.0.into_iter().map(websocket::tls::Certificate::new)
    }
}

/// A bounded set of additional WSS trust anchors used during certificate rotation.
pub struct WssTrustAnchors(Vec<Vec<u8>>);

impl WssTrustAnchors {
    /// Parses zero or more DER certificates or PEM bundles.
    pub fn from_documents(
        documents: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, NetworkBuildError> {
        parse_certificate_documents(documents)
            .map(Self)
            .map_err(|_| NetworkBuildError::InvalidWssTrustBundle)
    }

    fn single(certificate_der: Vec<u8>) -> Self {
        Self(vec![certificate_der])
    }

    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(Vec::as_slice)
    }

    fn into_upstream(self) -> impl Iterator<Item = websocket::tls::Certificate> {
        self.0.into_iter().map(websocket::tls::Certificate::new)
    }
}

/// A normalized, secret WSS private key document.
pub struct WssPrivateKey(SecretDocument);

impl WssPrivateKey {
    /// Accepts PKCS#1, PKCS#8, or SEC1 in DER or PEM form and normalizes it to DER.
    pub fn from_document(document: SecretDocument) -> Result<Self, NetworkBuildError> {
        if document.as_bytes().len() > MAX_WSS_PRIVATE_KEY_BYTES {
            return Err(NetworkBuildError::InvalidWssPrivateKey);
        }
        let normalized = if contains_pem_marker(document.as_bytes()) {
            let mut sections = SliceIter::<(SectionKind, Vec<u8>)>::new(document.as_bytes());
            let (kind, normalized) = sections
                .next()
                .ok_or(NetworkBuildError::InvalidWssPrivateKey)?
                .map_err(|_| NetworkBuildError::InvalidWssPrivateKey)?;
            if !matches!(
                kind,
                SectionKind::RsaPrivateKey | SectionKind::PrivateKey | SectionKind::EcPrivateKey
            ) || sections.next().is_some()
            {
                return Err(NetworkBuildError::InvalidWssPrivateKey);
            }
            PrivateKeyDer::try_from(normalized.as_slice())
                .map_err(|_| NetworkBuildError::InvalidWssPrivateKey)?;
            normalized
        } else {
            PrivateKeyDer::try_from(document.as_bytes())
                .map_err(|_| NetworkBuildError::InvalidWssPrivateKey)?;
            return Ok(Self(document));
        };
        Ok(Self(SecretDocument::new(normalized)))
    }

    fn unvalidated(private_key_der: SecretDocument) -> Self {
        Self(private_key_der)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn into_upstream(self) -> Vec<u8> {
        self.0.into_upstream_bytes()
    }
}

/// TLS material applied to the official libp2p WebSocket transport.
pub enum WssTransportConfig {
    Client {
        additional_trust: WssTrustAnchors,
    },
    Server {
        certificate_chain: WssCertificateChain,
        private_key: WssPrivateKey,
    },
}

impl WssTransportConfig {
    #[must_use]
    pub fn client(additional_ca_der: Option<Vec<u8>>) -> Self {
        Self::Client {
            additional_trust: additional_ca_der
                .map_or_else(|| WssTrustAnchors(Vec::new()), WssTrustAnchors::single),
        }
    }

    #[must_use]
    pub const fn client_with_trust(additional_trust: WssTrustAnchors) -> Self {
        Self::Client { additional_trust }
    }

    #[must_use]
    pub fn server(certificate_der: Vec<u8>, private_key_der: SecretDocument) -> Self {
        Self::Server {
            certificate_chain: WssCertificateChain::single(certificate_der),
            private_key: WssPrivateKey::unvalidated(private_key_der),
        }
    }

    #[must_use]
    pub const fn server_with_chain(
        certificate_chain: WssCertificateChain,
        private_key: WssPrivateKey,
    ) -> Self {
        Self::Server {
            certificate_chain,
            private_key,
        }
    }

    #[must_use]
    pub const fn is_server(&self) -> bool {
        matches!(self, Self::Server { .. })
    }

    /// Validates the server certificate/key encoding before the transport starts.
    pub fn validate_server_material(&self) -> Result<(), NetworkBuildError> {
        let Self::Server {
            certificate_chain,
            private_key,
        } = self
        else {
            return Err(NetworkBuildError::InvalidTlsMaterial);
        };
        PrivateKeyDer::try_from(private_key.as_bytes())
            .map_err(|_| NetworkBuildError::InvalidWssPrivateKey)?;
        for certificate in certificate_chain.iter() {
            let certificate = CertificateDer::from(certificate);
            webpki::EndEntityCert::try_from(&certificate)
                .map_err(NetworkBuildError::InvalidWssCertificate)?;
        }
        Ok(())
    }

    /// Runs the same rustls/libp2p builder used by the production transport.
    pub fn validate_tls_material(&self) -> Result<(), NetworkBuildError> {
        let mut builder = websocket::tls::Config::builder();
        match self {
            Self::Client { additional_trust } => {
                for certificate in additional_trust.iter() {
                    builder
                        .add_trust(&websocket::tls::Certificate::new(certificate.to_vec()))
                        .map_err(NetworkBuildError::WssTls)?;
                }
            }
            Self::Server {
                certificate_chain,
                private_key,
            } => {
                PrivateKeyDer::try_from(private_key.as_bytes())
                    .map_err(|_| NetworkBuildError::InvalidWssPrivateKey)?;
                let key = websocket::tls::PrivateKey::new(private_key.as_bytes().to_vec());
                let certificates = certificate_chain
                    .iter()
                    .map(|certificate| websocket::tls::Certificate::new(certificate.to_vec()));
                builder
                    .server(key, certificates)
                    .map_err(NetworkBuildError::WssTls)?;
            }
        }
        drop(builder.finish());
        Ok(())
    }

    /// Checks a WSS external address against the certificate's DNS/IP SANs.
    pub fn validate_server_for(
        &self,
        address: &RelayExternalAddress,
    ) -> Result<(), NetworkBuildError> {
        let Some(server_name) = address.wss_server_name() else {
            return Ok(());
        };
        let Self::Server {
            certificate_chain, ..
        } = self
        else {
            return Err(NetworkBuildError::InvalidTlsMaterial);
        };
        let certificate = CertificateDer::from(
            certificate_chain
                .leaf()
                .ok_or(NetworkBuildError::InvalidWssCertificateChain)?,
        );
        webpki::EndEntityCert::try_from(&certificate)
            .map_err(NetworkBuildError::InvalidWssCertificate)?
            .verify_is_valid_for_subject_name(server_name)
            .map_err(|_| NetworkBuildError::WssCertificateNameMismatch)
    }

    /// Duplicates public client trust while refusing to duplicate server private keys.
    #[must_use]
    pub fn clone_client(&self) -> Option<Self> {
        match self {
            Self::Client { additional_trust } => Some(Self::Client {
                additional_trust: WssTrustAnchors(additional_trust.0.clone()),
            }),
            Self::Server { .. } => None,
        }
    }
}

impl std::fmt::Debug for WssTransportConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client { additional_trust } => formatter
                .debug_struct("WssTransportConfig::Client")
                .field("additional_trust_count", &additional_trust.0.len())
                .finish(),
            Self::Server {
                certificate_chain, ..
            } => formatter
                .debug_struct("WssTransportConfig::Server")
                .field("certificate_count", &certificate_chain.0.len())
                .field("private_key", &"[REDACTED]")
                .finish(),
        }
    }
}

fn parse_certificate_documents(
    documents: impl IntoIterator<Item = Vec<u8>>,
) -> Result<Vec<Vec<u8>>, ()> {
    let mut certificates = Vec::new();
    let mut total_bytes = 0_usize;
    for document in documents {
        if contains_pem_marker(&document) {
            let mut found = false;
            for section in SliceIter::<(SectionKind, Vec<u8>)>::new(&document) {
                let (kind, certificate) = section.map_err(|_| ())?;
                if kind != SectionKind::Certificate {
                    return Err(());
                }
                found = true;
                total_bytes = total_bytes.checked_add(certificate.len()).ok_or(())?;
                certificates.push(certificate);
            }
            if !found {
                return Err(());
            }
        } else {
            total_bytes = total_bytes.checked_add(document.len()).ok_or(())?;
            certificates.push(document);
        }
        if certificates.len() > WSS_CERTIFICATE_LIMIT || total_bytes > MAX_WSS_CERTIFICATE_BYTES {
            return Err(());
        }
    }
    Ok(certificates)
}

fn contains_pem_marker(document: &[u8]) -> bool {
    document
        .windows(b"-----BEGIN".len())
        .any(|window| window == b"-----BEGIN")
}

/// Generates an ephemeral endpoint identity through the fallible project RNG boundary.
pub fn generate_identity(random: &mut impl SecureRandom) -> Result<Keypair, NetworkBuildError> {
    let mut seed = IdentitySeed::generate(random).map_err(NetworkBuildError::Random)?;
    Keypair::ed25519_from_bytes(seed.as_mut_bytes()).map_err(NetworkBuildError::Identity)
}

/// Builds the shared endpoint transport and its required relay-client behaviour.
pub fn build_endpoint_transport(
    identity: &Keypair,
    wss: WssTransportConfig,
) -> Result<(Boxed<(PeerId, StreamMuxerBox)>, relay::client::Behaviour), NetworkBuildError> {
    let peer_id = identity.public().to_peer_id();
    let (relay_transport, relay_behaviour) = relay::client::new(peer_id);
    let relay_transport = relay_transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(identity).map_err(NetworkBuildError::Security)?)
        .multiplex(yamux::Config::default())
        .timeout(TRANSPORT_TIMEOUT)
        .boxed();
    let direct = build_direct_transport(identity, wss)?;
    let combined = relay_transport
        .or_transport(direct)
        .map(|either, _| either.into_inner())
        .boxed();
    Ok((combined, relay_behaviour))
}

/// Builds the same direct transport stack for a relay server.
pub fn build_relay_transport(
    identity: &Keypair,
    wss: WssTransportConfig,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, NetworkBuildError> {
    build_direct_transport(identity, wss)
}

fn build_direct_transport(
    identity: &Keypair,
    wss: WssTransportConfig,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, NetworkBuildError> {
    let tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let tcp = dns::tokio::Transport::system(tcp).map_err(NetworkBuildError::Dns)?;
    let tcp = tcp
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(identity).map_err(NetworkBuildError::Security)?)
        .multiplex(yamux::Config::default())
        .timeout(TRANSPORT_TIMEOUT)
        .boxed();

    let websocket_tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let websocket_tcp =
        dns::tokio::Transport::system(websocket_tcp).map_err(NetworkBuildError::Dns)?;
    let mut websocket = websocket::Config::new(websocket_tcp);
    websocket.set_tls_config(websocket_tls(wss)?);
    let websocket = websocket
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(identity).map_err(NetworkBuildError::Security)?)
        .multiplex(yamux::Config::default())
        .timeout(TRANSPORT_TIMEOUT)
        .boxed();

    let quic = build_quic_transport(identity, TRANSPORT_TIMEOUT);

    Ok(quic
        .or_transport(websocket)
        .map(|either, _| either.into_inner())
        .or_transport(tcp)
        .map(|either, _| either.into_inner())
        .boxed())
}

fn build_quic_transport(identity: &Keypair, timeout: Duration) -> Boxed<(PeerId, StreamMuxerBox)> {
    libp2p::core::transport::timeout::TransportTimeout::new(
        quic::tokio::Transport::new(quic::Config::new(identity)),
        timeout,
    )
    .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
    .boxed()
}

fn websocket_tls(config: WssTransportConfig) -> Result<websocket::tls::Config, NetworkBuildError> {
    let mut builder = websocket::tls::Config::builder();
    match config {
        WssTransportConfig::Client { additional_trust } => {
            for certificate in additional_trust.into_upstream() {
                builder
                    .add_trust(&certificate)
                    .map_err(NetworkBuildError::WssTls)?;
            }
        }
        WssTransportConfig::Server {
            certificate_chain,
            private_key,
        } => {
            PrivateKeyDer::try_from(private_key.as_bytes())
                .map_err(|_| NetworkBuildError::InvalidWssPrivateKey)?;
            let key = websocket::tls::PrivateKey::new(private_key.into_upstream());
            builder
                .server(key, certificate_chain.into_upstream())
                .map_err(NetworkBuildError::WssTls)?;
        }
    }
    Ok(builder.finish())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        MAX_WSS_CERTIFICATE_BYTES, TRANSPORT_TIMEOUT, WSS_CERTIFICATE_LIMIT, WssCertificateChain,
        WssPrivateKey, WssTransportConfig, WssTrustAnchors, build_endpoint_transport,
        build_quic_transport, build_relay_transport, generate_identity,
    };
    use crate::{NetworkBuildError, RelayExternalAddress};
    use libp2p::core::Endpoint;
    use libp2p::core::transport::{DialOpts, PortUse, Transport as _};
    use libp2p::identity::Keypair;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
    use yonder_core::{RandomError, SecretDocument, SecureRandom};

    const TEST_SAN_CERTIFICATE_DER: &[u8] =
        include_bytes!("../../yon/tests/fixtures/localhost-test-cert.der");
    const TEST_SAN_PRIVATE_KEY_DER: &[u8] =
        include_bytes!("../../yon/tests/fixtures/localhost-test-key.der");

    const TEST_CERTIFICATE_PEM: &[u8] = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIICqTCCAZGgAwIBAgIJAJ616EfMEXGdMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0yNjA3MTYwNDAyMThaFw0zNjA3MTcwNDAyMThaMBQxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMf7dE3gf536J5QBG/+RbtxrE/Xa2d8ZgBX77S71HgTju+jh8eyIEtaOeuWZTxMAektbsfcOahNhlJNfYyMoz6hxCpqSqzymiidO+HOJKDDgZEd0NzagWKWItqSULGUL3GWc8cvzxIobjZpFIaguCc1X9Si1MYh5G+1rmE9ZglKlh7YhfgsXG7ipKybn/YTkFekG+uYFnMPAPYVkLz623AQVF5YOzwccQdT5KXyduILMoOgzPQaKzpsrBfAtBDgS8ut7Rj8eJjdescmdWlkrW2KU9gC5LprSJlKIzp4s5yLwxFM40g1FcMi1/reA037s/jOZM8rloyfssngeN5muL4ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEADTpHWdnQiHkv3Wrk9wctkthuYVvCqs0jCS0X7LIKgjfRxotbYJcCy2FUpjhbbmNgxbvTTY/Ad4sYnm8sD2yg1DAkwEoip6bi7fgIgBIE0fa743uOD84NuvyNdJgh5oQC+EsHAEeRMnA7HqYUir7AXBrN6fChGZwuDVLhcSR6h96cHbamB/v5a1SUWFKgndnwE8PhMLRdUmecp6E8FL0MeLEdeGQCRIeBBWIQzVxBO+6Y7PlzPZ85F1nMUqVdGeQt44Un6LIXBtQWOQOk9gU8UIZHqF50ZaK4KAkiLU6kCL6P+gkbBnreSWtWp2MeL3Sn3iBKB9WyjjyO7BgM3rP0Gw==\n",
        "-----END CERTIFICATE-----\n",
    )
    .as_bytes();
    const TEST_PRIVATE_KEY_PEM: &[u8] = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDH+3RN4H+d+ieUARv/kW7caxP12tnfGYAV++0u9R4E47vo4fHsiBLWjnrlmU8TAHpLW7H3DmoTYZSTX2MjKM+ocQqakqs8poonTvhziSgw4GRHdDc2oFiliLaklCxlC9xlnPHL88SKG42aRSGoLgnNV/UotTGIeRvta5hPWYJSpYe2IX4LFxu4qSsm5/2E5BXpBvrmBZzDwD2FZC8+ttwEFReWDs8HHEHU+Sl8nbiCzKDoMz0Gis6bKwXwLQQ4EvLre0Y/HiY3XrHJnVpZK1tilPYAuS6a0iZSiM6eLOci8MRTONINRXDItf63gNN+7P4zmTPK5aMn7LJ4HjeZri+BAgMBAAECggEATsduzJLokvoNh09ckTPgYTJJXauF8k4gWAizKbFjzvdLefUwEUaVbTIZlcLsFIc2peMMW0+xV8sz9U45Rot4KlnFnJi0niLY/50rYJAiZgavWjqc2YcXBLazhGfeiTu/6cOGuRphTSqHgMNE+/SO5faFXDDsv18+MiwVhwSyww1B4Hp6WzOwK33Ig1LLxeTt/W82XCLei9ip/ZUv6NsIbps721zTo35lrGVQJtkSwjrEUqvEImZuZW96Sf2rzkPPt9EjBTffwGr+09ebXRNhTYYRKkka3LQyPoDGMLnKn36C+4qScUdjqRSSgR3cBAzqQYi0PpFsdq2o+26fh/W4pQKBgQDZ0UfaUb367cLQfys2PDAPyIotOOliYYjgNjw1txoZ/1A01FQMNnD+6RQFnC/9x+8z0cKIqqdkVAdKZJo+POg7qEbuoQWPHLLPzu+OI8o9n5YtLnprJOIbUgz6UgoIf0GRYUH+M23QIeiW1sIo4ZQxBRlh77KBuu60OzHEmLAaVwKBgQDrCc2pqCxdI6Xj+F7u137s2PjBOm4Y5nultocz3WVQoiNzFl2C7GnYIPch1ResPV+Y4c42vfilr4aoJRy8ZyfC1o6PJLI342wZ1lzFvxg14NQjmSgI4laVlIndB0Un039rU6QCfLQW4nlm6MNgDrn8Ede0/PyVJ1x0rtydJBAN5wKBgQCOEdzl308k7hOVXnzW4ScQBGNr36UKEEfwxi87cfRKZKbx7lPrq07EVU5D4n3C77drezOBZJ3N6KjgswGP+rYWw0mQt+IiWDuhI35Inbt5ui9/xMMAQ4xe+YORehUlOauQoXkjznOfv54vVGBLveakmojVwjwSNdUgJUPu0RB7/QKBgQCdUKV4LdjrykVprb8Uy+Xnb14oLwyr2/DcvKwH+eKrMqrZiBm03LoHcCEZYwCCR13p/RFCMKrxcueFObnfHIhPb75hbuVeZPjg3kqgDMSOo1o6LXPPZncfjRkteIVAH96EHqqDA6aiPpmVWKwUaibv4Z1oRYBl8L+AVd3Ry+Z29wKBgQCbawmDWRXOCNk1TTk8JLqKMkaiA7qS+JuIuFKW1zPJjdDnM/o9Gun3XjXAAjQqsFbiqTcM60ONoROpUaMoQnMoxURwr+FHVvetWMwz7QiozH/8pGwFtb9+m1qon/cxcYd1QVnKG58Xy+8Yi1EIpSN1l2UH+80znSIflXvl47tbag==\n",
        "-----END PRIVATE KEY-----\n",
    )
    .as_bytes();

    struct FixedRandom(Result<u8, RandomError>);

    impl SecureRandom for FixedRandom {
        fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
            match self.0 {
                Ok(value) => {
                    destination.fill(value);
                    Ok(())
                }
                Err(_) => Err(RandomError),
            }
        }
    }

    #[test]
    fn endpoint_and_relay_direct_stacks_construct() {
        assert_eq!(TRANSPORT_TIMEOUT, std::time::Duration::from_secs(8));
        let identity = Keypair::generate_ed25519();
        assert!(build_endpoint_transport(&identity, WssTransportConfig::client(None)).is_ok());
        assert!(build_relay_transport(&identity, WssTransportConfig::client(None)).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quic_connection_setup_obeys_the_shared_transport_timeout() {
        let identity = Keypair::generate_ed25519();
        let mut transport = build_quic_transport(&identity, std::time::Duration::ZERO);
        let address = "/ip4/127.0.0.1/udp/9/quic-v1".parse().unwrap();
        let dial = transport
            .dial(
                address,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap();

        let error = dial.await.unwrap_err();
        assert_eq!(error.to_string(), "Timeout has been reached");
    }

    #[test]
    fn invalid_tls_material_fails_before_upstream_panic_boundary() {
        let identity = Keypair::generate_ed25519();
        assert!(
            build_relay_transport(
                &identity,
                WssTransportConfig::server(vec![1], SecretDocument::new(vec![2])),
            )
            .is_err()
        );
        assert!(
            build_endpoint_transport(&identity, WssTransportConfig::client(Some(vec![1]))).is_err()
        );
    }

    #[test]
    fn valid_wss_server_and_additional_client_trust_construct() {
        let certificate = CertificateDer::from_pem_slice(TEST_CERTIFICATE_PEM)
            .unwrap()
            .as_ref()
            .to_vec();
        let private_key = PrivateKeyDer::from_pem_slice(TEST_PRIVATE_KEY_PEM)
            .unwrap()
            .secret_der()
            .to_vec();
        let identity = Keypair::generate_ed25519();

        assert!(
            build_relay_transport(
                &identity,
                WssTransportConfig::server(certificate.clone(), SecretDocument::new(private_key),),
            )
            .is_ok()
        );
        assert!(
            build_endpoint_transport(&identity, WssTransportConfig::client(Some(certificate)))
                .is_ok()
        );
    }

    #[test]
    fn tls_documents_use_upstream_pem_parsing_and_enforce_bundle_bounds() {
        let pem_chain = [TEST_CERTIFICATE_PEM, TEST_CERTIFICATE_PEM].concat();
        let chain = WssCertificateChain::from_documents([pem_chain]).unwrap();
        let key = WssPrivateKey::from_document(SecretDocument::new(TEST_PRIVATE_KEY_PEM.to_vec()))
            .unwrap();
        let server = WssTransportConfig::server_with_chain(chain, key);
        assert!(format!("{server:?}").contains("certificate_count: 2"));

        let trust = WssTrustAnchors::from_documents([TEST_CERTIFICATE_PEM.to_vec()]).unwrap();
        let client = WssTransportConfig::client_with_trust(trust);
        assert!(format!("{client:?}").contains("additional_trust_count: 1"));

        assert!(matches!(
            WssCertificateChain::from_documents(Vec::<Vec<u8>>::new()),
            Err(NetworkBuildError::InvalidWssCertificateChain)
        ));
        assert!(matches!(
            WssCertificateChain::from_documents([
                b"-----BEGIN CERTIFICATE-----\ninvalid\n".to_vec()
            ]),
            Err(NetworkBuildError::InvalidWssCertificateChain)
        ));
        assert!(matches!(
            WssCertificateChain::from_documents([
                [TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM].concat()
            ]),
            Err(NetworkBuildError::InvalidWssCertificateChain)
        ));
        assert!(matches!(
            WssTrustAnchors::from_documents(
                (0..=WSS_CERTIFICATE_LIMIT).map(|_| TEST_SAN_CERTIFICATE_DER.to_vec())
            ),
            Err(NetworkBuildError::InvalidWssTrustBundle)
        ));
        assert!(matches!(
            WssTrustAnchors::from_documents([vec![0; MAX_WSS_CERTIFICATE_BYTES + 1]]),
            Err(NetworkBuildError::InvalidWssTrustBundle)
        ));
        assert!(matches!(
            WssPrivateKey::from_document(SecretDocument::new(
                b"-----BEGIN PRIVATE KEY-----\ninvalid\n".to_vec()
            )),
            Err(NetworkBuildError::InvalidWssPrivateKey)
        ));
        assert!(matches!(
            WssPrivateKey::from_document(SecretDocument::new(
                [TEST_PRIVATE_KEY_PEM, TEST_CERTIFICATE_PEM].concat()
            )),
            Err(NetworkBuildError::InvalidWssPrivateKey)
        ));
    }

    #[test]
    fn server_material_and_dns_ip_sans_are_validated_before_listening() {
        let client = WssTransportConfig::client(None);
        assert!(!client.is_server());
        assert!(client.validate_server_material().is_err());

        let server = WssTransportConfig::server(
            TEST_SAN_CERTIFICATE_DER.to_vec(),
            SecretDocument::new(TEST_SAN_PRIVATE_KEY_DER.to_vec()),
        );
        assert!(server.is_server());
        server.validate_server_material().unwrap();

        for address in [
            "/dns4/localhost/tcp/443/tls/ws",
            "/ip4/127.0.0.1/tcp/443/tls/ws",
            "/ip4/127.0.0.1/tcp/443",
        ] {
            let address: RelayExternalAddress = address.parse().unwrap();
            server.validate_server_for(&address).unwrap();
        }
        for address in [
            "/dns4/relay.example/tcp/443/tls/ws",
            "/ip4/127.0.0.2/tcp/443/tls/ws",
        ] {
            let address: RelayExternalAddress = address.parse().unwrap();
            assert!(matches!(
                server.validate_server_for(&address),
                Err(NetworkBuildError::WssCertificateNameMismatch)
            ));
        }

        let plain: RelayExternalAddress = "/ip4/127.0.0.1/tcp/443".parse().unwrap();
        client.validate_server_for(&plain).unwrap();

        let secure: RelayExternalAddress = "/dns4/localhost/tcp/443/tls/ws".parse().unwrap();
        assert!(matches!(
            client.validate_server_for(&secure),
            Err(NetworkBuildError::InvalidTlsMaterial)
        ));
        let invalid_server = WssTransportConfig::server(vec![1], SecretDocument::new(vec![1]));
        assert!(matches!(
            invalid_server.validate_server_for(&secure),
            Err(NetworkBuildError::InvalidWssCertificate(_))
        ));

        let invalid_key = WssTransportConfig::server(
            TEST_SAN_CERTIFICATE_DER.to_vec(),
            SecretDocument::new(vec![1]),
        );
        assert!(matches!(
            invalid_key.validate_server_material(),
            Err(NetworkBuildError::InvalidWssPrivateKey)
        ));
        let invalid_certificate = WssTransportConfig::server(
            vec![1],
            SecretDocument::new(TEST_SAN_PRIVATE_KEY_DER.to_vec()),
        );
        assert!(matches!(
            invalid_certificate.validate_server_material(),
            Err(NetworkBuildError::InvalidWssCertificate(_))
        ));
    }

    #[test]
    fn identity_generation_is_fallible_and_tls_debug_is_redacted() {
        let mut fixed = FixedRandom(Ok(7));
        assert!(generate_identity(&mut fixed).is_ok());
        let mut failing = FixedRandom(Err(RandomError));
        assert!(generate_identity(&mut failing).is_err());

        let client = WssTransportConfig::client(Some(vec![1, 2, 3]));
        assert!(format!("{client:?}").contains("additional_trust_count: 1"));
        let server = WssTransportConfig::server(vec![1, 2], SecretDocument::new(vec![9, 9, 9]));
        let debug = format!("{server:?}");
        assert!(debug.contains("certificate_count: 1"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("9, 9, 9"));

        let cloned = client.clone_client().unwrap();
        assert!(format!("{cloned:?}").contains("additional_trust_count: 1"));
        assert!(WssTransportConfig::client(None).clone_client().is_some());
        assert!(server.clone_client().is_none());
    }
}
