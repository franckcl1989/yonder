#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use yonder_core::ConnectionCode;

fuzz_target!(|input: &[u8]| {
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = text.parse::<ConnectionCode>();
    }
});
