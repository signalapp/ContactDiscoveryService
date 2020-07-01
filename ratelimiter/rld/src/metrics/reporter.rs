//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::sync::*;
use std::thread;
use std::time::*;

use super::*;
use crate::util::thread::{StopJoinHandle, StopState};

pub trait Reporter: Send {
    fn report(&mut self, registry: &MetricRegistry);
}

pub struct PeriodicReporter<ReporterTy> {
    reporter:   ReporterTy,
    registry:   MetricRegistry,
    interval:   Duration,
    stop_state: Arc<StopState>,
}

impl<ReporterTy> PeriodicReporter<ReporterTy>
where ReporterTy: Reporter + 'static
{
    pub fn new(reporter: ReporterTy, registry: MetricRegistry, interval: Duration) -> Self {
        Self {
            reporter,
            registry,
            interval,
            stop_state: Default::default(),
        }
    }

    pub fn start(mut self) -> StopJoinHandle<()> {
        let stop_state = self.stop_state.clone();
        let join_handle = thread::spawn(move || {
            while self.stop_state.sleep_while_running(self.interval) {
                self.reporter.report(&self.registry);
            }
        });
        StopJoinHandle::new(stop_state, join_handle)
    }
}
