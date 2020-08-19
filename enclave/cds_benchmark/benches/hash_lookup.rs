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

const PHONE_DB_ELEMENTS: [usize; 7] = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000];
const QUERY_PHONE_ELEMENTS: [usize; 7] = [1, 256, 512, 1024, 2048, 4096, 8192];

fn bench_hash_lookup_one_query_phone_varying_phone_db(criterion: &mut Criterion) {
    let mut bench_group = criterion.benchmark_group("hash_lookup_one_query_phone_varying_phone_db");

    // Bench querying one phone against various database sizes.
    let static_query_size = 1;
    for phone_count in &PHONE_DB_ELEMENTS {
        bench_group.throughput(Throughput::Elements(*phone_count as u64));
        bench_with_inputs(
            &mut bench_group,
            BenchmarkId::from_parameter(phone_count),
            static_query_size,
            *phone_count,
        );
    }
}

fn bench_hash_lookup_large_db_varying_query_phone(criterion: &mut Criterion) {
    let mut bench_group = criterion.benchmark_group("hash_lookup_large_db_varying_query_phone");

    // Bench querying against a large phone data base with various
    // query sizes. These should all be the same for a constant time
    // lookup algorightm.
    let static_map_size = PHONE_DB_ELEMENTS[PHONE_DB_ELEMENTS.len() - 1];
    for query_size in &QUERY_PHONE_ELEMENTS {
        bench_group.throughput(Throughput::Elements(*query_size as u64));
        bench_with_inputs(
            &mut bench_group,
            BenchmarkId::from_parameter(query_size),
            *query_size,
            static_map_size,
        );
    }
}

fn perf_hash_lookup(criterion: &mut Criterion) {
    let mut bench_group = criterion.benchmark_group("perf_hash_lookup");

    let static_map_size = 1_000_000;
    let query_size = 1024;
    bench_group.throughput(Throughput::Elements(query_size as u64));
    bench_with_inputs(
        &mut bench_group,
        BenchmarkId::from_parameter(query_size),
        query_size,
        static_map_size,
    );
}

fn bench_with_inputs(benchmark_group: &mut BenchmarkGroup<WallTime>, bench_id: BenchmarkId, query_size: usize, phone_count: usize) {
    let in_phones: Vec<Phone> = black_box(vec![0; phone_count]);
    let in_uuids: Vec<Uuid> = black_box(vec![Uuid { data64: [0, 0] }; phone_count]);
    let query_phones: Vec<Phone> = black_box(vec![0; query_size]);
    let mut query_phone_results_data: Vec<Uuid> = vec![Uuid { data64: [0, 0] }; query_phones.len()];

    benchmark_group.bench_function(bench_id, |bencher: &mut Bencher| {
        bencher.iter(|| {
            match hash_lookup(
                &in_phones,
                in_uuids.as_slice(),
                &query_phones,
                query_phone_results_data.as_mut_slice(),
            ) {
                0 => {}
                error => panic!(
                    "hash_lookup() failed with code: {}, query_size: {}, phone_count: {}",
                    error, query_size, phone_count
                ),
            }
        })
    });
}

criterion_group!(
    benches,
    bench_hash_lookup_one_query_phone_varying_phone_db,
    bench_hash_lookup_large_db_varying_query_phone,
    perf_hash_lookup,
);
criterion_main!(benches);
