//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

extern crate x86;

struct BenchState {
    start: u64,
    sum:   u64,
    count: u64,
}
fn with_bench<F, R>(fun: F) -> R
where F: for<'a> FnOnce(&'a mut BenchState) -> R {
    thread_local! {
        static BENCH: std::cell::UnsafeCell<BenchState> = std::cell::UnsafeCell::new(BenchState { start: 0, sum: 0, count: 0 });
    }
    BENCH.with(|bench| unsafe { fun(&mut *bench.get()) })
}
pub fn bench_reset() {
    with_bench(|bench| {
        bench.sum = 0;
        bench.count = 0;
    });
}
pub fn bench_start() {
    with_bench(|bench| bench.start = unsafe { x86::current::time::rdtscp() });
}
pub fn bench_stop() {
    with_bench(|bench| {
        if bench.start != 0 {
            let end = unsafe { x86::current::time::rdtscp() };
            bench.sum += end - bench.start;
            bench.count += 1;
            bench.start = 0;
            if bench.sum > 10000000000 {
                println!(
                    "{} laps in {} cycles = {} cycles / lap",
                    bench.count,
                    bench.sum,
                    bench.sum / bench.count
                );
                bench.sum = 0;
                bench.count = 0;
            }
        }
    });
}
