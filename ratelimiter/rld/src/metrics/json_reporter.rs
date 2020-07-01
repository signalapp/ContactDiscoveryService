//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::*;

use exponential_decay_histogram::Snapshot;
use failure::ResultExt;
use http::header::HeaderValue;
use http::uri;
use http::{HttpTryFrom, Uri};
use hyper::client::connect::Connect;
use hyper::{Body, Client, Method, Request};
use log::{debug, info, warn};
use nix::unistd;
use serde_derive::*;

use super::*;

pub struct JsonReporter<ConnectorTy> {
    uri:     Uri,
    client:  Client<ConnectorTy, Body>,
    runtime: tokio::runtime::Runtime,
}

#[derive(Default, Deserialize, Serialize)]
pub struct MetricsReport(HashMap<String, MetricReport>);

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum MetricReport {
    Counter(u64),
    Gauge(f64),
    Meter(MeterReport),
    Timer(TimerReport),
    Histogram(HistogramReport),
}

#[derive(Deserialize, Serialize)]
struct MeterReport {
    count: u64,
    mean:  f64,
    m1:    f64,
    m5:    f64,
    m15:   f64,
}

#[derive(Deserialize, Serialize)]
struct SnapshotReport {
    max:    i64,
    mean:   f64,
    min:    i64,
    stddev: f64,
    median: i64,
    p75:    i64,
    p95:    i64,
    p98:    i64,
    p99:    i64,
    p999:   i64,
}

#[derive(Deserialize, Serialize)]
struct TimerReport {
    rate:     MeterReport,
    duration: SnapshotReport,
}

#[derive(Deserialize, Serialize)]
struct HistogramReport {
    count:    u64,
    #[serde(flatten)]
    snapshot: SnapshotReport,
}

impl<ConnectorTy> JsonReporter<ConnectorTy>
where ConnectorTy: Connect + 'static
{
    pub fn new(token: &str, hostname: &str, maybe_our_hostname: Option<&str>, connector: ConnectorTy) -> Result<Self, failure::Error> {
        let our_hostname = match maybe_our_hostname {
            Some(our_hostname) => our_hostname.into(),
            None => {
                let mut hostname_buf = [0; 255];
                let hostname_cstr = unistd::gethostname(&mut hostname_buf).context("error getting hostname")?;
                Cow::Owned(hostname_cstr.to_string_lossy().into_owned())
            }
        };

        info!("starting json metrics reporter for {} as {}", hostname, our_hostname);

        let path_and_query = format!("/report/metrics?t={}&h={}", token, our_hostname);
        let mut uri_parts = uri::Parts::default();
        uri_parts.scheme = Some(uri::Scheme::HTTPS);
        uri_parts.authority = Some(uri::Authority::try_from(hostname).context("invalid hostname")?);
        uri_parts.path_and_query = Some(uri::PathAndQuery::try_from(path_and_query.as_str()).context("invalid token or host")?);
        let uri = Uri::try_from(uri_parts).context("invalid hostname, token, or host")?;

        let runtime = tokio::runtime::Builder::new()
            .core_threads(1)
            .name_prefix("json-reporter-")
            .build()
            .context("error starting tokio runtime for json-reporter")?;
        let client = Client::builder().executor(runtime.executor()).build(connector);

        Ok(Self { uri, client, runtime })
    }
}

impl<ConnectorTy> Reporter for JsonReporter<ConnectorTy>
where ConnectorTy: Connect + 'static
{
    fn report(&mut self, registry: &MetricRegistry) {
        debug!("reporting metrics...");

        let metrics_report = MetricsReport::from(registry);
        let encoded_request = match serde_json::to_vec(&metrics_report) {
            Ok(encoded_request) => encoded_request,
            Err(serde_error) => {
                warn!("error encoding json metrics: {}", serde_error);
                return;
            }
        };

        let mut hyper_request = Request::new(Body::from(encoded_request));
        *hyper_request.method_mut() = Method::POST;
        *hyper_request.uri_mut() = self.uri.clone();
        hyper_request
            .headers_mut()
            .insert("Content-Type", HeaderValue::from_static("application/json"));

        let response = self.client.request(hyper_request);

        match self.runtime.block_on(response) {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("sent {} metrics successfully", metrics_report.0.len());
                } else {
                    info!("http error sending metrics: {}", response.status());
                }
            }
            Err(hyper_error) => {
                info!("error sending metrics: {}", hyper_error);
            }
        }
    }
}

impl From<&MetricRegistry> for MetricsReport {
    fn from(registry: &MetricRegistry) -> Self {
        let mut report = Self::default();
        let now = Instant::now();

        for (metric_name, metric) in registry.metrics() {
            let metric_report = MetricReport::from_metric(&metric, now);
            report.0.insert(metric_name, metric_report);
        }
        report
    }
}

//
// MetricReport impls
//

impl MetricReport {
    fn from_metric(metric: &Metric, now: Instant) -> Self {
        match metric {
            Metric::Counter(counter) => MetricReport::Counter(counter.count()),
            Metric::Gauge(gauge) => MetricReport::Gauge(gauge.value()),
            Metric::Meter(meter) => MetricReport::Meter(MeterReport::from_meter(meter, now)),
            Metric::Histogram(histogram) => MetricReport::Histogram(histogram.into()),
            Metric::Timer(timer) => MetricReport::Timer(TimerReport::from_timer(timer, now)),
        }
    }
}

impl MeterReport {
    fn from_meter(meter: &Meter, now: Instant) -> Self {
        let elapsed = meter.tick(now);
        let count = meter.count();
        Self {
            count,
            mean: (count as f64) / ((elapsed.as_nanos() as f64) / 1e9),
            m1: meter.m1_rate(),
            m5: meter.m5_rate(),
            m15: meter.m15_rate(),
        }
    }
}

impl From<&Histogram> for HistogramReport {
    fn from(histogram: &Histogram) -> Self {
        let snapshot = histogram.snapshot();
        Self {
            count:    snapshot.count(),
            snapshot: SnapshotReport::from(&snapshot),
        }
    }
}

impl From<&Snapshot> for SnapshotReport {
    fn from(snapshot: &Snapshot) -> Self {
        Self {
            max:    snapshot.max(),
            mean:   snapshot.mean(),
            min:    snapshot.min(),
            stddev: snapshot.stddev(),
            median: snapshot.value(0.5),
            p75:    snapshot.value(0.75),
            p95:    snapshot.value(0.95),
            p98:    snapshot.value(0.98),
            p99:    snapshot.value(0.99),
            p999:   snapshot.value(0.999),
        }
    }
}

impl TimerReport {
    fn from_timer(timer: &Timer, now: Instant) -> Self {
        Self {
            rate:     MeterReport::from_meter(timer.meter(), now),
            duration: HistogramReport::from(timer.histogram()).snapshot,
        }
    }
}
