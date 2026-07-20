#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use yonder_core::wire::auth::{
    AuthClientFinish, AuthClientHello, AuthServerResponse, Authenticated, PakeContext,
};
use yonder_core::wire::registry::{RegistryRequest, RegistryResponse};
use yonder_core::wire::resolve::{ResolveRequest, ResolveResponse};
use yonder_core::wire::terminal::{TerminalExit, TerminalHello, TerminalReady, TerminalResize};
use yonder_core::{Locator, PeerIdBytes};

fuzz_target!(|input: &[u8]| {
    let _ = RegistryRequest::decode(input);
    let _ = RegistryResponse::decode(input);
    let _ = ResolveRequest::decode(input);
    let _ = ResolveResponse::decode(input);
    let _ = AuthClientHello::decode(input);
    let _ = AuthServerResponse::decode(input);
    let _ = AuthClientFinish::decode(input);
    let _ = Authenticated::decode(input);
    let _ = TerminalHello::decode(input);
    let _ = TerminalResize::decode(input);
    let _ = TerminalExit::decode(input);
    let _ = TerminalReady::decode(input);

    let fallback = [0_u8];
    let peer_len = input.len().clamp(1, PeerIdBytes::MAX_LEN);
    let controller_bytes = if input.is_empty() {
        fallback.as_slice()
    } else {
        &input[..peer_len]
    };
    let target_bytes = if input.is_empty() {
        fallback.as_slice()
    } else {
        &input[input.len().saturating_sub(PeerIdBytes::MAX_LEN)..]
    };
    let controller =
        PeerIdBytes::new(controller_bytes).expect("bounded non-empty controller PeerId");
    let target = PeerIdBytes::new(target_bytes).expect("bounded non-empty target PeerId");

    let mut locator_bytes = [0_u8; 3];
    let locator_len = input.len().min(locator_bytes.len());
    locator_bytes[..locator_len].copy_from_slice(&input[..locator_len]);
    locator_bytes[0] &= 0x0f;
    let locator = Locator::from_wire(locator_bytes).expect("masked locator");

    let mut controller_nonce = [0_u8; 32];
    let controller_nonce_len = input.len().min(controller_nonce.len());
    controller_nonce[..controller_nonce_len].copy_from_slice(&input[..controller_nonce_len]);
    let target_nonce_bytes = &input[input.len().saturating_sub(32)..];
    let mut target_nonce = [0_u8; 32];
    target_nonce[..target_nonce_bytes.len()].copy_from_slice(target_nonce_bytes);

    let context = PakeContext::new(
        locator,
        &controller,
        &target,
        &controller_nonce,
        &target_nonce,
    );
    assert!(!context.as_bytes().is_empty());
});
