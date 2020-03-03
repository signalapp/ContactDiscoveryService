/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use cds_enclave::test::ratelimit_set::*;
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
