//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::*;
use std::convert::*;
use std::sync::*;

use log::error;

use super::*;

#[derive(Default)]
pub struct MetricRegistries {
    registries: Mutex<HashMap<&'static str, MetricRegistry>>,
}

#[derive(Clone, Default)]
pub struct MetricRegistry {
    metrics: Arc<Mutex<HashMap<String, Metric>>>,
}

//
// MetricRegistries impls
//

lazy_static::lazy_static! {
    static ref GLOBAL_METRIC_REGISTRIES: MetricRegistries = Default::default();
}

impl MetricRegistries {
    pub fn global() -> &'static MetricRegistries {
        &*GLOBAL_METRIC_REGISTRIES
    }

    pub fn get_or_create(&self, name: &'static str) -> MetricRegistry {
        let mut registries = match self.registries.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        registries.entry(name).or_insert_with(MetricRegistry::default).clone()
    }
}

//
// MetricRegistry impls
//

impl MetricRegistry {
    pub fn metrics(&self) -> Vec<(String, Metric)> {
        let metrics = match self.metrics.lock() {
            Ok(guard) => guard,
            Err(poison_error) => poison_error.into_inner(),
        };
        metrics.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn metric<MetricTy>(&self, name: &str) -> MetricTy
    where
        MetricTy: TryFrom<Metric, Error = ()> + Clone + Default,
        Metric: From<MetricTy>,
    {
        match self.get_or_insert_metric(name.to_string()) {
            Ok(meter) => meter,
            Err(_metric) => {
                error!("tried to add meter with existing metric of different type: {}", name);
                MetricTy::default()
            }
        }
    }

    fn get_or_insert_metric<MetricTy>(&self, name: String) -> Result<MetricTy, Metric>
    where
        MetricTy: TryFrom<Metric, Error = ()> + Clone + Default,
        Metric: From<MetricTy>,
    {
        let mut metrics = match self.metrics.lock() {
            Ok(guard) => guard,
            Err(poison_error) => poison_error.into_inner(),
        };
        let metric = metrics.entry(name).or_insert_with(|| Metric::from(MetricTy::default()));
        match MetricTy::try_from(metric.clone()) {
            Ok(metric) => Ok(metric),
            Err(()) => Err(metric.clone()),
        }
    }
}
