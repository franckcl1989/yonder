use crate::RelayExternalAddress;
use crate::error::NetworkBuildError;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::{Transport, upgrade};
use libp2p::identity::Keypair;
use libp2p::{PeerId, dns, noise, quic, relay, tcp, websocket, yamux};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::time::Duration;
use yonder_core::{IdentitySeed, SecretDocument, SecureRandom};

const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(8);

/// TLS material applied to the official libp2p WebSocket transport.
pub enum WssTransportConfig {
    Client {
        additional_ca_der: Option<Vec<u8>>,
    },
    Server {
        certificate_der: Vec<u8>,
        private_key_der: SecretDocument,
    },
}

impl WssTransportConfig {
    #[must_use]
    pub const fn client(additional_ca_der: Option<Vec<u8>>) -> Self {
        Self::Client { additional_ca_der }
    }

    #[must_use]
    pub const fn server(certificate_der: Vec<u8>, private_key_der: SecretDocument) -> Self {
        Self::Server {
            certificate_der,
            private_key_der,
        }
    }

    #[must_use]
    pub const fn is_server(&self) -> bool {
        matches!(self, Self::Server { .. })
    }

    /// Validates the server certificate/key encoding before the transport starts.
    pub fn validate_server_material(&self) -> Result<(), NetworkBuildError> {
        let Self::Server {
            certificate_der,
            private_key_der,
        } = self
        else {
            return Err(NetworkBuildError::InvalidTlsMaterial);
        };
        PrivateKeyDer::try_from(private_key_der.as_bytes())
            .map_err(|_| NetworkBuildError::InvalidTlsMaterial)?;
        let certificate = CertificateDer::from(certificate_der.as_slice());
        webpki::EndEntityCert::try_from(&certificate)
            .map(|_| ())
            .map_err(|_| NetworkBuildError::InvalidTlsMaterial)
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
            certificate_der, ..
        } = self
        else {
            return Err(NetworkBuildError::InvalidTlsMaterial);
        };
        let certificate = CertificateDer::from(certificate_der.as_slice());
        webpki::EndEntityCert::try_from(&certificate)
            .map_err(|_| NetworkBuildError::InvalidTlsMaterial)?
            .verify_is_valid_for_subject_name(server_name)
            .map_err(|_| NetworkBuildError::WssCertificateNameMismatch)
    }

    /// Duplicates public client trust while refusing to duplicate server private keys.
    #[must_use]
    pub fn clone_client(&self) -> Option<Self> {
        match self {
            Self::Client { additional_ca_der } => Some(Self::client(additional_ca_der.clone())),
            Self::Server { .. } => None,
        }
    }
}

impl std::fmt::Debug for WssTransportConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client { additional_ca_der } => formatter
                .debug_struct("WssTransportConfig::Client")
                .field("has_additional_ca", &additional_ca_der.is_some())
                .finish(),
            Self::Server {
                certificate_der, ..
            } => formatter
                .debug_struct("WssTransportConfig::Server")
                .field("certificate_len", &certificate_der.len())
                .field("private_key", &"[REDACTED]")
                .finish(),
        }
    }
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
        WssTransportConfig::Client { additional_ca_der } => {
            if let Some(certificate) = additional_ca_der {
                builder
                    .add_trust(&websocket::tls::Certificate::new(certificate))
                    .map_err(|_| NetworkBuildError::InvalidTlsMaterial)?;
            }
        }
        WssTransportConfig::Server {
            certificate_der,
            private_key_der,
        } => {
            PrivateKeyDer::try_from(private_key_der.as_bytes())
                .map_err(|_| NetworkBuildError::InvalidTlsMaterial)?;
            let key = websocket::tls::PrivateKey::new(private_key_der.into_upstream_bytes());
            let certificate = websocket::tls::Certificate::new(certificate_der);
            builder
                .server(key, [certificate])
                .map_err(|_| NetworkBuildError::InvalidTlsMaterial)?;
        }
    }
    Ok(builder.finish())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        TRANSPORT_TIMEOUT, WssTransportConfig, build_endpoint_transport, build_quic_transport,
        build_relay_transport, generate_identity,
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
            Err(NetworkBuildError::InvalidTlsMaterial)
        ));
    }

    #[test]
    fn identity_generation_is_fallible_and_tls_debug_is_redacted() {
        let mut fixed = FixedRandom(Ok(7));
        assert!(generate_identity(&mut fixed).is_ok());
        let mut failing = FixedRandom(Err(RandomError));
        assert!(generate_identity(&mut failing).is_err());

        let client = WssTransportConfig::client(Some(vec![1, 2, 3]));
        assert!(format!("{client:?}").contains("has_additional_ca: true"));
        let server = WssTransportConfig::server(vec![1, 2], SecretDocument::new(vec![9, 9, 9]));
        let debug = format!("{server:?}");
        assert!(debug.contains("certificate_len: 2"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("9, 9, 9"));

        let cloned = client.clone_client().unwrap();
        assert!(format!("{cloned:?}").contains("has_additional_ca: true"));
        assert!(WssTransportConfig::client(None).clone_client().is_some());
        assert!(server.clone_client().is_none());
    }
}
