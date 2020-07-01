//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use rld_config::ratelimiter::*;

use crate::limits::leaky_bucket::LeakyBucketParameters;

//
// FrontendRateLimitConfig impls
//

impl From<RateLimiterRateLimitConfig> for LeakyBucketParameters {
    fn from(config: RateLimiterRateLimitConfig) -> Self {
        Self {
            size:      config.bucketSize,
            leak_rate: config.leakRatePerMinute / 60.0,
        }
    }
}
