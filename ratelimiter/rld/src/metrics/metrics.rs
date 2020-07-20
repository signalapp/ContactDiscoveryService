//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::convert::*;
use std::sync::atomic::*;
use std::sync::*;
use std::time::*;

use exponential_decay_histogram::*;

pub const METER_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub enum Metric {
    Counter(Counter),
    Gauge(Gauge),
    Meter(Meter),
    Histogram(Histogram),
    Timer(Timer),
}

#[derive(Clone, Default)]
pub struct Counter {
    count: Arc<AtomicU64>,
}

pub struct CounterGuard {
    counter: Counter,
    value:   u64,
}

#[derive(Clone, Default)]
pub struct Gauge {
    value: Arc<AtomicU64>,
}

#[derive(Clone, Default)]
pub struct Meter {
    shared: Arc<MeterShared>,
}

#[derive(Clone, Default)]
pub struct Histogram {
    sample: Arc<Mutex<ExponentialDecayHistogram>>,
}

#[derive(Clone, Default)]
pub struct Timer {
    meter:     Meter,
    histogram: Histogram,
}

pub struct TimerGuard<'a> {
    timer: &'a Timer,
    start: Instant,
}

struct MeterShared {
    start_time: Instant,
    last_tick:  AtomicU64,
    tick_total: AtomicU64,
    count:      AtomicU64,
    m1_rate:    ExponentiallyWeightedMovingAverage,
    m5_rate:    ExponentiallyWeightedMovingAverage,
    m15_rate:   ExponentiallyWeightedMovingAverage,
}

struct ExponentiallyWeightedMovingAverage {
    alpha:   f64,
    average: AtomicU64,
}

//
// Metric impls
//

impl From<Counter> for Metric {
    fn from(counter: Counter) -> Self {
        Metric::Counter(counter)
    }
}

impl From<Gauge> for Metric {
    fn from(gauge: Gauge) -> Self {
        Metric::Gauge(gauge)
    }
}

impl From<Meter> for Metric {
    fn from(meter: Meter) -> Self {
        Metric::Meter(meter)
    }
}

impl From<Histogram> for Metric {
    fn from(histogram: Histogram) -> Self {
        Metric::Histogram(histogram)
    }
}

impl From<Timer> for Metric {
    fn from(timer: Timer) -> Self {
        Metric::Timer(timer)
    }
}

//
// Counter impls
//

impl Counter {
    #[allow(dead_code)]
    pub fn inc(&self, value: u64) {
        self.count.fetch_add(value, Ordering::SeqCst);
    }

    pub fn dec(&self, value: u64) {
        self.count.fetch_sub(value, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    pub fn guard(&self, value: u64) -> CounterGuard {
        self.inc(value);
        CounterGuard {
            counter: self.clone(),
            value,
        }
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

impl Eq for Counter {}
impl PartialEq for Counter {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.count, &other.count)
    }
}

impl TryFrom<Metric> for Counter {
    type Error = ();

    fn try_from(metric: Metric) -> Result<Self, Self::Error> {
        match metric {
            Metric::Counter(counter) => Ok(counter),
            _ => Err(()),
        }
    }
}

//
// CounterGuard impls
//

impl CounterGuard {
    #[allow(dead_code)]
    pub fn update(&mut self, new_counter: &Counter) {
        if new_counter != &self.counter {
            self.counter.dec(self.value);
            new_counter.inc(self.value);
            self.counter = new_counter.clone();
        }
    }
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        self.counter.dec(self.value);
    }
}

//
// Gauge impls
//

impl Gauge {
    #[allow(dead_code)]
    pub fn update(&self, value: impl num_traits::AsPrimitive<f64>) {
        let value = value.as_();
        self.value.store(value.to_bits(), Ordering::SeqCst);
    }

    pub fn value(&self) -> f64 {
        f64::from_bits(self.value.load(Ordering::SeqCst))
    }
}

impl TryFrom<Metric> for Gauge {
    type Error = ();

    fn try_from(metric: Metric) -> Result<Self, Self::Error> {
        match metric {
            Metric::Gauge(gauge) => Ok(gauge),
            _ => Err(()),
        }
    }
}

//
// Meter impls
//

impl Meter {
    pub fn mark(&self) {
        self.inc(1);
    }

    pub fn inc(&self, value: u64) {
        self.tick_to(self.shared.start_time.elapsed());
        self.shared.count.fetch_add(value, Ordering::SeqCst);
        self.shared.tick_total.fetch_add(value, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    pub fn set(&self, new_count: u64) {
        self.tick_to(self.shared.start_time.elapsed());
        let old_count = self.shared.count.swap(new_count, Ordering::SeqCst);
        if let Some(count_diff) = new_count.checked_sub(old_count) {
            if old_count != 0 && count_diff != 0 {
                self.shared.tick_total.fetch_add(count_diff, Ordering::SeqCst);
            }
        }
    }

    pub fn tick(&self, now: Instant) -> Duration {
        let elapsed = now.duration_since(self.shared.start_time);
        self.tick_to(elapsed);
        elapsed
    }

    pub fn count(&self) -> u64 {
        self.shared.count.load(Ordering::SeqCst)
    }

    pub fn m1_rate(&self) -> f64 {
        self.shared.m1_rate.rate()
    }

    pub fn m5_rate(&self) -> f64 {
        self.shared.m5_rate.rate()
    }

    pub fn m15_rate(&self) -> f64 {
        self.shared.m15_rate.rate()
    }

    fn tick_to(&self, current_tick: Duration) {
        let current_tick = current_tick.as_secs();
        let last_tick = self.shared.last_tick.load(Ordering::SeqCst);
        let elapsed = current_tick.saturating_sub(last_tick);
        let interval = METER_INTERVAL.as_secs();
        if elapsed > interval {
            let ticks_elapsed = elapsed / interval;
            let new_last_tick = current_tick.saturating_sub(elapsed % interval);
            if self.shared.last_tick.compare_and_swap(last_tick, new_last_tick, Ordering::SeqCst) == last_tick {
                let total = self.shared.tick_total.swap(0, Ordering::SeqCst);
                let rate = (total as f64) / (METER_INTERVAL.as_secs() as f64);
                self.shared.m1_rate.tick(rate, ticks_elapsed);
                self.shared.m5_rate.tick(rate, ticks_elapsed);
                self.shared.m15_rate.tick(rate, ticks_elapsed);
            }
        }
    }
}

impl TryFrom<Metric> for Meter {
    type Error = ();

    fn try_from(metric: Metric) -> Result<Self, Self::Error> {
        match metric {
            Metric::Meter(meter) => Ok(meter),
            _ => Err(()),
        }
    }
}

impl Default for MeterShared {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            last_tick:  Default::default(),
            tick_total: Default::default(),
            count:      Default::default(),
            m1_rate:    ExponentiallyWeightedMovingAverage::new(ExponentiallyWeightedMovingAverage::default_alpha(1.0)),
            m5_rate:    ExponentiallyWeightedMovingAverage::new(ExponentiallyWeightedMovingAverage::default_alpha(5.0)),
            m15_rate:   ExponentiallyWeightedMovingAverage::new(ExponentiallyWeightedMovingAverage::default_alpha(15.0)),
        }
    }
}

//
// Histogram impls
//

impl TryFrom<Metric> for Histogram {
    type Error = ();

    fn try_from(metric: Metric) -> Result<Self, Self::Error> {
        match metric {
            Metric::Histogram(histogram) => Ok(histogram),
            _ => Err(()),
        }
    }
}

//
// Timer impls
//

impl TryFrom<Metric> for Timer {
    type Error = ();

    fn try_from(metric: Metric) -> Result<Self, Self::Error> {
        match metric {
            Metric::Timer(timer) => Ok(timer),
            _ => Err(()),
        }
    }
}

//
// ExponentiallyWeightedMovingAverage impls
//

impl ExponentiallyWeightedMovingAverage {
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha,
            average: AtomicU64::new(0.0f64.to_bits()),
        }
    }

    pub fn default_alpha(secs: f64) -> f64 {
        1.0f64 - (-5.0f64 / 60.0 / secs).exp()
    }

    pub fn rate(&self) -> f64 {
        f64::from_bits(self.average.load(Ordering::SeqCst))
    }

    pub fn tick(&self, rate: f64, ticks: u64) {
        if ticks != 0 {
            let old_average = f64::from_bits(self.average.load(Ordering::SeqCst));
            let mut new_average = old_average + (self.alpha * (rate - old_average));
            if ticks > 1 {
                new_average *= (1.0f64 - self.alpha).powi((ticks - 1) as i32);
            }
            self.average.store(new_average.to_bits(), Ordering::SeqCst);
        }
    }
}

//
// Timer impls
//

impl Timer {
    pub fn time(&self) -> TimerGuard<'_> {
        TimerGuard {
            timer: self,
            start: Instant::now(),
        }
    }

    pub fn update(&self, value: Duration) {
        if let Ok(integer_value) = i64::try_from(value.as_millis()) {
            self.meter.mark();
            self.histogram.update(integer_value);
        }
    }

    pub fn meter(&self) -> &Meter {
        &self.meter
    }

    pub fn histogram(&self) -> &Histogram {
        &self.histogram
    }
}

//
// TimerGuard impls
//

impl<'a> TimerGuard<'a> {
    pub fn stop(self) {
        drop(self);
    }
}

impl<'a> Drop for TimerGuard<'a> {
    fn drop(&mut self) {
        self.timer.update(self.start.elapsed());
    }
}

//
// Histogram impls
//

impl Histogram {
    pub fn update(&self, value: i64) {
        let mut sample_guard = match self.sample.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        sample_guard.update(value);
    }

    pub fn snapshot(&self) -> Snapshot {
        let sample_guard = match self.sample.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        sample_guard.snapshot()
    }
}
