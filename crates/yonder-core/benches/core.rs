#![forbid(unsafe_code)]

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use yonder_core::wire::registry::{RegistryRequest, RegistryResponse};
use yonder_core::wire::terminal::{TerminalHello, TerminalResize};
use yonder_core::{
    ConnectionCode, DirectRateLimiter, Locator, PakeSecret, RetryAfter, TerminalSize, TerminalValue,
};

fn connection_code(criterion: &mut Criterion) {
    let code = ConnectionCode::new(
        Locator::new(0xA_BCDE).expect("benchmark locator is valid"),
        PakeSecret::from_u64(0x0FED_CBA9_8765_4321).expect("benchmark secret is valid"),
    );
    let encoded = code.expose().to_string();

    criterion.bench_function("connection_code/encode", |bencher| {
        bencher.iter(|| black_box(&code).expose().to_string())
    });
    criterion.bench_function("connection_code/decode", |bencher| {
        bencher.iter(|| black_box(encoded.as_str()).parse::<ConnectionCode>())
    });
}

fn wire_protocol(criterion: &mut Criterion) {
    let request = RegistryRequest::Reclaim(Locator::new(0xA_BCDE).expect("valid locator")).encode();
    let response =
        RegistryResponse::Retry(RetryAfter::from_millis(250).expect("valid retry")).encode();
    let hello = TerminalHello::new(
        TerminalSize::new(120, 40).expect("valid size"),
        TerminalValue::new("xterm-256color").expect("valid terminal value"),
        TerminalValue::new("truecolor").expect("valid terminal value"),
    )
    .encode();
    let resize = TerminalResize::new(TerminalSize::new(160, 50).expect("valid size")).encode();

    criterion.bench_function("wire/registry_request_decode", |bencher| {
        bencher.iter(|| RegistryRequest::decode(black_box(&request)))
    });
    criterion.bench_function("wire/registry_response_decode", |bencher| {
        bencher.iter(|| RegistryResponse::decode(black_box(&response)))
    });
    criterion.bench_function("wire/terminal_hello_decode", |bencher| {
        bencher.iter(|| TerminalHello::decode(black_box(hello.as_slice())))
    });
    criterion.bench_function("wire/terminal_resize_decode", |bencher| {
        bencher.iter(|| TerminalResize::decode(black_box(&resize)))
    });
}

fn rate_limiter(criterion: &mut Criterion) {
    let resolve = yonder_core::RelayResourceConfig::default().resolve();
    let limit = resolve.global().rate_limit();
    let burst = resolve.global().burst().get();
    criterion.bench_function("rate_limiter/check_burst", |bencher| {
        bencher.iter_batched(
            || DirectRateLimiter::new(limit),
            |limiter| {
                for _ in 0..burst {
                    black_box(limiter.check());
                }
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, connection_code, wire_protocol, rate_limiter);
criterion_main!(benches);
