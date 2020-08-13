//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

extern crate cds_benchmark;
use cds_benchmark::*;
use criterion::measurement::WallTime;
use criterion::{black_box, criterion_group, criterion_main, Bencher, BenchmarkGroup, BenchmarkId, Criterion, Throughput};

fn bench_hash_lookup_varying_map_per_map_elem_throughput(criterion: &mut Criterion) {
    let mut bench_group = criterion.benchmark_group("hash_lookup_varying_map_per_map_elem_throughput");

    // Bench querying one phone against various database sizes.
    let static_query_size = 1;
    let ten: usize = 10;
    let map_sizes: Vec<usize> = vec![40000, 25 * ten.pow(6), 60 * ten.pow(6)];
    for phone_count in map_sizes {
        bench_group.throughput(Throughput::Elements(phone_count as u64));
        bench_with_inputs(
            &mut bench_group,
            BenchmarkId::from_parameter(phone_count),
            static_query_size,
            phone_count,
        );
    }
}

fn bench_hash_lookup_varying_map_per_query_elem_throughput(criterion: &mut Criterion) {
    let mut bench_group = criterion.benchmark_group("hash_lookup_varying_map_per_query_elem_throughput");

    // Bench querying one phone against various database sizes.
    let static_query_size = 1;
    let ten: usize = 10;
    let map_sizes: Vec<usize> = vec![40000, 25 * ten.pow(6), 60 * ten.pow(6)];
    for phone_count in map_sizes {
        bench_group.throughput(Throughput::Elements(static_query_size as u64));
        bench_with_inputs(
            &mut bench_group,
            BenchmarkId::from_parameter(phone_count),
            static_query_size,
            phone_count,
        );
    }
}

fn bench_hash_lookup_varying_query_per_query_elem_throughput(criterion: &mut Criterion) {
    let mut bench_group = criterion.benchmark_group("hash_lookup_varying_query_per_query_elem");
    // Bench querying against a large dataset with various query sizes. These should all be the
    // same
    let ten: usize = 10;
    let static_map_size = 60 * ten.pow(6);
    for query_size in vec![1, 100, 2048, 4096, 8096, 21000] {
        bench_group.throughput(Throughput::Elements(query_size as u64));
        bench_with_inputs(
            &mut bench_group,
            BenchmarkId::from_parameter(query_size),
            query_size,
            static_map_size,
        );
    }
}

fn bench_hash_lookup_varying_query_per_map_elem_throughput(criterion: &mut Criterion) {
    let mut bench_group = criterion.benchmark_group("hash_lookup_varying_query_per_map_elem");
    // Bench querying against a large dataset with various query sizes. These should all be the
    // same
    let ten: usize = 10;
    let static_map_size = 60 * ten.pow(6);
    for query_size in vec![1, 100, 2048, 4096, 8096, 21000] {
        bench_group.throughput(Throughput::Elements(static_map_size as u64));
        bench_with_inputs(
            &mut bench_group,
            BenchmarkId::from_parameter(query_size),
            query_size,
            static_map_size,
        );
    }
}

fn bench_with_inputs(benchmark_group: &mut BenchmarkGroup<WallTime>, bench_id: BenchmarkId, query_size: usize, phone_count: usize) {
    let in_phones: Vec<Phone> = black_box(vec![0; phone_count]);
    let in_uuids: Vec<Uuid> = black_box(vec![Uuid { data64: [0, 0] }; phone_count]);
    let query_phones: Vec<Phone> = black_box(vec![0; query_size]);
    let mut query_phone_results_data: Vec<Uuid> = vec![Uuid { data64: [0, 0] }; query_phones.len()];

    benchmark_group.bench_function(bench_id, |bencher: &mut Bencher| {
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

criterion_group!(
    benches,
    bench_hash_lookup_varying_map_per_map_elem_throughput,
    bench_hash_lookup_varying_map_per_query_elem_throughput,
    bench_hash_lookup_varying_query_per_map_elem_throughput,
    bench_hash_lookup_varying_query_per_query_elem_throughput
);
criterion_main!(benches);
