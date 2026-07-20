use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use sha2::Sha512;
use thiserror::Error;
use yonder_core::{Pake, PakeSecret, PeerIdBytes};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

struct YonderSuite;

impl CipherSuite for YonderSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

/// OPAQUE failures are deliberately collapsed at the product boundary.
#[derive(Debug, Error)]
pub enum OpaquePakeError {
    #[error("the OPAQUE exchange was rejected")]
    Rejected,
    #[error("the configured OPAQUE wire size does not match the selected ciphersuite")]
    WireSize,
}

/// An in-memory, one-use password file and its private OPAQUE server setup.
pub struct OpaqueRegistration {
    setup: ServerSetup<YonderSuite>,
    password_file: ServerRegistration<YonderSuite>,
    credential_id: PeerIdBytes,
}

/// Client login state plus the short-lived password needed by OPAQUE's final step.
pub struct OpaqueClientState {
    inner: Option<ClientLogin<YonderSuite>>,
    secret: [u8; 8],
    server: PeerIdBytes,
}

impl OpaqueClientState {
    fn into_parts(mut self) -> (ClientLogin<YonderSuite>, [u8; 8], PeerIdBytes) {
        let state = self
            .inner
            .take()
            .expect("OPAQUE client state is consumed exactly once");
        let secret = std::mem::take(&mut self.secret);
        (state, secret, self.server.clone())
    }
}

impl Drop for OpaqueClientState {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Server login state plus the exact transcript context needed for key confirmation.
pub struct OpaqueServerState {
    inner: Option<ServerLogin<YonderSuite>>,
    context: [u8; 256],
    context_len: u16,
    server: PeerIdBytes,
}

impl OpaqueServerState {
    fn new(
        inner: ServerLogin<YonderSuite>,
        context: &[u8],
        server: PeerIdBytes,
    ) -> Result<Self, OpaquePakeError> {
        if context.len() > 256 {
            return Err(OpaquePakeError::WireSize);
        }
        let context_len = context.len() as u16;
        let mut bytes = [0_u8; 256];
        bytes[..context.len()].copy_from_slice(context);
        Ok(Self {
            inner: Some(inner),
            context: bytes,
            context_len,
            server,
        })
    }

    fn into_parts(mut self) -> (ServerLogin<YonderSuite>, [u8; 256], u16, PeerIdBytes) {
        let state = self
            .inner
            .take()
            .expect("OPAQUE server state is consumed exactly once");
        let context = std::mem::replace(&mut self.context, [0; 256]);
        (state, context, self.context_len, self.server.clone())
    }
}

impl Drop for OpaqueServerState {
    fn drop(&mut self) {
        self.context.zeroize();
        self.context_len.zeroize();
    }
}

/// Secret key confirmed by both OPAQUE participants.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpaqueSessionKey([u8; 64]);

impl AsRef<[u8]> for OpaqueSessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for OpaqueSessionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpaqueSessionKey([REDACTED])")
    }
}

/// Safe adapter around the approved `opaque-ke` ciphersuite.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpaquePake;

impl Pake for OpaquePake {
    type Error = OpaquePakeError;
    type Registration = OpaqueRegistration;
    type ClientState = OpaqueClientState;
    type ServerState = OpaqueServerState;
    type SessionKey = OpaqueSessionKey;

    fn register(
        &mut self,
        server: &PeerIdBytes,
        secret: &PakeSecret,
    ) -> Result<Self::Registration, Self::Error> {
        let mut rng = OsRng;
        let setup = ServerSetup::<YonderSuite>::new(&mut rng);
        let client = ClientRegistration::<YonderSuite>::start(&mut rng, secret.expose_bytes())
            .map_err(|_| OpaquePakeError::Rejected)?;
        let response = ServerRegistration::<YonderSuite>::start(
            &setup,
            RegistrationRequest::deserialize(&client.message.serialize())
                .map_err(|_| OpaquePakeError::Rejected)?,
            server.as_bytes(),
        )
        .map_err(|_| OpaquePakeError::Rejected)?;
        let upload = client
            .state
            .finish(
                &mut rng,
                secret.expose_bytes(),
                RegistrationResponse::deserialize(&response.message.serialize())
                    .map_err(|_| OpaquePakeError::Rejected)?,
                ClientRegistrationFinishParameters::new(
                    server_identifiers(server),
                    Some(&argon2()?),
                ),
            )
            .map_err(|_| OpaquePakeError::Rejected)?;
        let password_file = ServerRegistration::finish(
            RegistrationUpload::<YonderSuite>::deserialize(&upload.message.serialize())
                .map_err(|_| OpaquePakeError::Rejected)?,
        );
        Ok(OpaqueRegistration {
            setup,
            password_file,
            credential_id: server.clone(),
        })
    }

    fn client_start(
        &mut self,
        server: &PeerIdBytes,
        secret: &PakeSecret,
    ) -> Result<(Self::ClientState, [u8; 96]), Self::Error> {
        let mut rng = OsRng;
        let result = ClientLogin::<YonderSuite>::start(&mut rng, secret.expose_bytes())
            .map_err(|_| OpaquePakeError::Rejected)?;
        let message = exact_array(result.message.serialize().as_slice())?;
        Ok((
            OpaqueClientState {
                inner: Some(result.state),
                secret: *secret.expose_bytes(),
                server: server.clone(),
            },
            message,
        ))
    }

    fn client_finish(
        &mut self,
        state: Self::ClientState,
        response: &[u8; 320],
        context: &[u8],
    ) -> Result<([u8; 64], Self::SessionKey), Self::Error> {
        let response =
            CredentialResponse::deserialize(response).map_err(|_| OpaquePakeError::Rejected)?;
        let (state, secret, server) = state.into_parts();
        let secret = Zeroizing::new(secret);
        let mut rng = OsRng;
        let result = state
            .finish(
                &mut rng,
                secret.as_slice(),
                response,
                ClientLoginFinishParameters::new(
                    Some(context),
                    server_identifiers(&server),
                    Some(&argon2()?),
                ),
            )
            .map_err(|_| OpaquePakeError::Rejected)?;
        let finish = exact_array(result.message.serialize().as_slice())?;
        let session_key = exact_array(result.session_key.as_slice())?;
        Ok((finish, OpaqueSessionKey(session_key)))
    }

    fn server_start(
        &mut self,
        registration: &Self::Registration,
        request: &[u8; 96],
        context: &[u8],
    ) -> Result<(Self::ServerState, [u8; 320]), Self::Error> {
        let request =
            CredentialRequest::deserialize(request).map_err(|_| OpaquePakeError::Rejected)?;
        let mut rng = OsRng;
        let result = ServerLogin::start(
            &mut rng,
            &registration.setup,
            Some(registration.password_file.clone()),
            request,
            registration.credential_id.as_bytes(),
            ServerLoginParameters {
                context: Some(context),
                identifiers: server_identifiers(&registration.credential_id),
            },
        )
        .map_err(|_| OpaquePakeError::Rejected)?;
        let response = exact_array(result.message.serialize().as_slice())?;
        Ok((
            OpaqueServerState::new(result.state, context, registration.credential_id.clone())?,
            response,
        ))
    }

    fn server_finish(
        &mut self,
        state: Self::ServerState,
        finish: &[u8; 64],
    ) -> Result<Self::SessionKey, Self::Error> {
        let finish =
            CredentialFinalization::deserialize(finish).map_err(|_| OpaquePakeError::Rejected)?;
        let (state, context, context_len, server) = state.into_parts();
        let context = Zeroizing::new(context);
        let result = state
            .finish(
                finish,
                ServerLoginParameters {
                    context: Some(&context[..usize::from(context_len)]),
                    identifiers: server_identifiers(&server),
                },
            )
            .map_err(|_| OpaquePakeError::Rejected)?;
        Ok(OpaqueSessionKey(exact_array(
            result.session_key.as_slice(),
        )?))
    }
}

fn server_identifiers(server: &PeerIdBytes) -> Identifiers<'_> {
    Identifiers {
        client: None,
        server: Some(server.as_bytes()),
    }
}

fn argon2() -> Result<Argon2<'static>, OpaquePakeError> {
    let parameters = Params::new(19_456, 2, 1, None).map_err(|_| OpaquePakeError::Rejected)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters))
}

fn exact_array<const LENGTH: usize>(bytes: &[u8]) -> Result<[u8; LENGTH], OpaquePakeError> {
    bytes.try_into().map_err(|_| OpaquePakeError::WireSize)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{OpaquePake, OpaquePakeError, exact_array};
    use yonder_core::{Pake, PakeSecret, PeerIdBytes};

    #[test]
    fn both_sides_confirm_the_same_key() {
        let mut opaque = OpaquePake;
        let server = PeerIdBytes::new(b"target-peer-id").unwrap();
        let secret = PakeSecret::from_u64(0x0123_4567_89AB_CDEF).unwrap();
        let registration = opaque.register(&server, &secret).unwrap();
        let (client, ke1) = opaque.client_start(&server, &secret).unwrap();
        let context = b"bound-yonder-context";
        let (server, ke2) = opaque.server_start(&registration, &ke1, context).unwrap();
        let (ke3, client_key) = opaque.client_finish(client, &ke2, context).unwrap();
        let server_key = opaque.server_finish(server, &ke3).unwrap();
        assert_eq!(client_key.as_ref(), server_key.as_ref());
        assert_eq!(format!("{client_key:?}"), "OpaqueSessionKey([REDACTED])");
    }

    #[test]
    fn a_wrong_secret_is_rejected() {
        let mut opaque = OpaquePake;
        let server = PeerIdBytes::new(b"target-peer-id").unwrap();
        let expected = PakeSecret::from_u64(1).unwrap();
        let wrong = PakeSecret::from_u64(2).unwrap();
        let registration = opaque.register(&server, &expected).unwrap();
        let (client, ke1) = opaque.client_start(&server, &wrong).unwrap();
        let (server, ke2) = opaque
            .server_start(&registration, &ke1, b"context")
            .unwrap();
        assert!(opaque.client_finish(client, &ke2, b"context").is_err());
        drop(server);
    }

    #[test]
    fn malformed_wire_messages_and_oversized_contexts_are_rejected() {
        let mut opaque = OpaquePake;
        let server = PeerIdBytes::new(b"target-peer-id").unwrap();
        let secret = PakeSecret::from_u64(3).unwrap();
        let registration = opaque.register(&server, &secret).unwrap();

        assert!(matches!(
            opaque.server_start(&registration, &[0; 96], b"context"),
            Err(OpaquePakeError::Rejected)
        ));
        let (client, ke1) = opaque.client_start(&server, &secret).unwrap();
        assert!(matches!(
            opaque.server_start(&registration, &ke1, &[0; 257]),
            Err(OpaquePakeError::WireSize)
        ));
        assert!(matches!(
            opaque.client_finish(client, &[0; 320], b"context"),
            Err(OpaquePakeError::Rejected)
        ));

        let (_, ke1) = opaque.client_start(&server, &secret).unwrap();
        let (server_state, _) = opaque
            .server_start(&registration, &ke1, b"context")
            .unwrap();
        assert!(matches!(
            opaque.server_finish(server_state, &[0; 64]),
            Err(OpaquePakeError::Rejected)
        ));
        assert!(matches!(
            exact_array::<2>(&[1]),
            Err(OpaquePakeError::WireSize)
        ));
        assert!(matches!(
            exact_array::<64>(&[]),
            Err(OpaquePakeError::WireSize)
        ));
        assert!(matches!(
            exact_array::<96>(&[]),
            Err(OpaquePakeError::WireSize)
        ));
        assert!(matches!(
            exact_array::<320>(&[]),
            Err(OpaquePakeError::WireSize)
        ));
        assert_eq!(exact_array::<2>(&[1, 2]).unwrap(), [1, 2]);
        assert_eq!(
            OpaquePakeError::Rejected.to_string(),
            "the OPAQUE exchange was rejected"
        );
    }

    #[test]
    fn a_different_server_identifier_is_rejected() {
        let mut opaque = OpaquePake;
        let server = PeerIdBytes::new(b"target-peer-id").unwrap();
        let wrong_server = PeerIdBytes::new(b"different-target").unwrap();
        let secret = PakeSecret::from_u64(4).unwrap();
        let registration = opaque.register(&server, &secret).unwrap();
        let (client, ke1) = opaque.client_start(&wrong_server, &secret).unwrap();
        let (_, ke2) = opaque
            .server_start(&registration, &ke1, b"context")
            .unwrap();
        assert!(opaque.client_finish(client, &ke2, b"context").is_err());
    }
}
