#![forbid(unsafe_code)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use yonder_net::{
    CandidateId, CandidatePath, EstablishedOrder, PathCandidate, PathPolicy, PingSamples,
    QualityPathPolicy, TransportKind,
};

fn rank_paths(criterion: &mut Criterion) {
    let candidates = (0_u64..8)
        .map(|index| {
            let mut samples = PingSamples::new();
            samples.push(Duration::from_micros(800 + index * 10));
            samples.push(Duration::from_micros(900 + index * 10));
            samples.push(Duration::from_micros(850 + index * 10));
            PathCandidate::new(
                CandidateId::new(index),
                samples,
                if index % 3 == 0 {
                    CandidatePath::Relayed
                } else {
                    CandidatePath::Direct
                },
                if index % 2 == 0 {
                    TransportKind::Quic
                } else {
                    TransportKind::Tcp
                },
                EstablishedOrder::new(index),
            )
        })
        .collect::<Vec<_>>();

    criterion.bench_function("path/select_eight", |bencher| {
        bencher.iter(|| QualityPathPolicy.select(black_box(&candidates)))
    });
}

criterion_group!(benches, rank_paths);
criterion_main!(benches);
