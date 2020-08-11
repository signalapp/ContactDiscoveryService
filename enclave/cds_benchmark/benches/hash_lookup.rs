//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

extern crate cds_benchmark;
use cds_benchmark::*;
use criterion::{black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput};

fn bench_hash_lookup(criterion: &mut Criterion) {
    let mut benchmark_group = criterion.benchmark_group("hash_lookup");

    let phone_count: usize = 40000;

    let in_phones: Vec<Phone> = black_box(vec![0; phone_count]);
    let in_uuids: Vec<Uuid> = black_box(vec![Uuid { data64: [0, 0] }; phone_count]);

    let query_phones: Vec<Phone> = black_box(vec![0; 1]);
    let mut query_phone_results_data: Vec<Uuid> = vec![Uuid { data64: [0, 0] }; query_phones.len()];

    benchmark_group.throughput(Throughput::Elements(phone_count as u64));

    benchmark_group.bench_function(BenchmarkId::from_parameter(phone_count), |bencher: &mut Bencher| {
        bencher.iter(|| {
            let _ = hash_lookup(
                &in_phones,
                in_uuids.as_slice(),
                &query_phones,
                query_phone_results_data.as_mut_slice(),
            );
        })
    });
}

criterion_group!(benches, bench_hash_lookup);
criterion_main!(benches);
