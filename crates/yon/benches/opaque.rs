#![forbid(unsafe_code)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use yon::pake::OpaquePake;
use yon::terminal::TerminalChunk;
use yonder_core::{Pake, PakeSecret, PeerIdBytes};

fn opaque_round_trip(criterion: &mut Criterion) {
    let peer = PeerIdBytes::new(b"benchmark-target-peer").expect("valid peer id bytes");
    let secret = PakeSecret::from_u64(0x0123_4567_89AB_CDEF).expect("valid PAKE secret");
    let mut opaque = OpaquePake;
    let registration = opaque
        .register(&peer, &secret)
        .expect("registration succeeds");

    criterion.bench_function("opaque/login_round_trip", |bencher| {
        bencher.iter(|| {
            let (client, ke1) = opaque
                .client_start(&peer, &secret)
                .expect("client start succeeds");
            let (server, ke2) = opaque
                .server_start(&registration, &ke1, b"benchmark-context")
                .expect("server start succeeds");
            let (ke3, client_key) = opaque
                .client_finish(client, &ke2, b"benchmark-context")
                .expect("client finish succeeds");
            let server_key = opaque
                .server_finish(server, &ke3)
                .expect("server finish succeeds");
            black_box((client_key, server_key));
        })
    });
}

fn fixed_terminal_buffer_copy(criterion: &mut Criterion) {
    let source = [0xA5_u8; 16 * 1024];

    criterion.bench_function("terminal/fixed_buffer_copy_16k", |bencher| {
        bencher.iter(|| {
            let mut chunk = TerminalChunk::new();
            chunk.writable().copy_from_slice(black_box(&source));
            chunk
                .set_len(source.len())
                .expect("benchmark payload matches the frozen chunk capacity");
            black_box(chunk);
        });
    });
}

criterion_group!(benches, opaque_round_trip, fixed_terminal_buffer_copy);
criterion_main!(benches);
