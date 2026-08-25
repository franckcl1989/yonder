#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use yonder_core::wire::file_transfer::{
    FileTransferMessage, TransferDirection, TransferSide, WireSession,
};
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

    let mut transfers = [
        WireSession::new(TransferDirection::Upload, TransferSide::Controller),
        WireSession::new(TransferDirection::Upload, TransferSide::Host),
        WireSession::new(TransferDirection::Download, TransferSide::Controller),
        WireSession::new(TransferDirection::Download, TransferSide::Host),
    ];
    for (index, frame) in input.split(|byte| *byte == 0).take(256).enumerate() {
        let Ok(message) = FileTransferMessage::decode_frame(frame) else {
            continue;
        };
        let transfer = &mut transfers[index % transfers.len()];
        let before = transfer.state();
        let result = if input.get(index).is_some_and(|byte| byte & 1 == 0) {
            transfer.send(&message)
        } else {
            transfer.receive(&message)
        };
        if result.is_err() {
            assert_eq!(transfer.state(), before);
        }
    }
});
