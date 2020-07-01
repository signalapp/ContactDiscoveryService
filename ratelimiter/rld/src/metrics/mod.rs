//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

mod json_reporter;
#[macro_use]
mod macros;
mod metrics;
mod registry;
mod reporter;

pub use json_reporter::*;
pub use metrics::*;
pub use registry::*;
pub use reporter::*;

use crate::constants;

lazy_static::lazy_static! {
    pub static ref METRICS: MetricRegistry = MetricRegistries::global().get_or_create(constants::METRICS_NAME);
}

pub fn metric_name<T: AsRef<str>>(parts: impl IntoIterator<Item = T> + Clone) -> String {
    let name_len = parts.clone().into_iter().map(|part| part.as_ref().len() + 1).sum();
    let mut name = String::with_capacity(name_len);
    for part in parts {
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(part.as_ref());
    }
    name
}
