//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

extern crate cds_benchmark;
use cds_benchmark::*;
use criterion::{black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput};

fn bench_ratelimit_set_add(criterion: &mut Criterion) {
    let mut benchmark_group = criterion.benchmark_group("ratelimit_set_add");

    let ratelimit_slot_count = 40000;

    let mut ratelimit_slots = black_box(vec![0; ratelimit_slot_count as usize * 8]);
    let query_phones = black_box(vec![0; 1]);

    benchmark_group.throughput(Throughput::Elements(ratelimit_slot_count));

    benchmark_group.bench_function(BenchmarkId::from_parameter(ratelimit_slot_count), |bencher: &mut Bencher| {
        bencher.iter(|| ratelimit_set_add(&mut ratelimit_slots, &query_phones))
    });
}

criterion_group!(benches, bench_ratelimit_set_add);
criterion_main!(benches);
