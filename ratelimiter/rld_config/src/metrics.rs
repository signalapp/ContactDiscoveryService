//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use serde_derive::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub reporters: Vec<MetricsReporterConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
pub enum MetricsReporterConfig {
    Json(JsonMetricsReporterConfig),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonMetricsReporterConfig {
    pub hostname: String,

    pub token: String,

    pub intervalSeconds: Option<u64>,
}
