//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use kbupd_util::hex;
use serde_derive::Deserialize;

use crate::metrics::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterConfig {
    pub api: RateLimiterApiConfig,

    pub enclaves: Vec<RateLimiterEnclaveConfig>,

    pub attestation: RateLimiterAttestationConfig,

    pub control: RateLimiterControlConfig,

    pub metrics: Option<MetricsConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterApiConfig {
    pub listenHostPort: String,

    #[serde(with = "hex")]
    pub userAuthenticationTokenSharedSecret: Vec<u8>,

    #[serde(with = "hex")]
    pub discoveryIdSecret: Vec<u8>,

    pub discoveryRateLimitSetSize: u32,

    #[serde(default)]
    pub denyDiscovery: bool,

    #[serde(default)]
    pub limits: RateLimiterApiRateLimitsConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterApiRateLimitsConfig {
    pub attestation: RateLimiterRateLimitConfig,

    pub discovery: RateLimiterRateLimitConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterRateLimitConfig {
    pub bucketSize: u64,

    pub leakRatePerMinute: f64,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterEnclaveConfig {
    pub mrenclave: String,

    pub debug: bool,

    pub initialCapacity: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterAttestationConfig {
    pub hostName: String,

    pub endPoint: String,

    pub apiVersion: Option<String>,

    pub apiKey: String,

    #[serde(with = "hex::SerdeFixedLengthHex")]
    pub spid: [u8; 16],

    #[serde(default)]
    pub acceptGroupOutOfDate: bool,

    #[serde(default)]
    pub disabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterControlConfig {
    pub listenHostPort: String,
}

//
// RateLimiterApiRateLimitsConfig impls
//

impl Default for RateLimiterApiRateLimitsConfig {
    fn default() -> Self {
        Self {
            attestation: RateLimiterRateLimitConfig {
                bucketSize:        10,
                leakRatePerMinute: 10.0,
            },
            discovery:   RateLimiterRateLimitConfig {
                bucketSize:        10,
                leakRatePerMinute: 10.0,
            },
        }
    }
}
