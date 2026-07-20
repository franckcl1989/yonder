#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use yonder_core::{SessionEvent, TargetSession};

const EVENTS: [SessionEvent; 9] = [
    SessionEvent::BeginAuthentication,
    SessionEvent::AuthenticationSucceeded,
    SessionEvent::AuthenticationFailed,
    SessionEvent::TerminalStreamsReady,
    SessionEvent::TerminalStartFailed,
    SessionEvent::TerminalReadyFlushed,
    SessionEvent::ConnectionLost,
    SessionEvent::ExtraConnection,
    SessionEvent::ShellExited,
];

fuzz_target!(|input: &[u8]| {
    let mut session = TargetSession::new();
    let mut consumed = false;
    for byte in input.iter().copied().take(256) {
        let before = session.state();
        let result = session.apply(EVENTS[usize::from(byte) % EVENTS.len()]);
        if result.is_err() {
            assert_eq!(session.state(), before);
        }
        consumed |= session.is_consumed();
        assert!(!consumed || session.is_consumed());
    }
});
