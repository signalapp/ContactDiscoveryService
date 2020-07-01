//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use std::io::Read;

use serde_derive::Deserialize;
use serde_yaml;

use crate::base64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub client: Option<ClientConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub clientCertificatePkcs12: Option<Base64ConfigValue>,

    pub caCertificates: Vec<ClientCaCertificateConfig>,

    pub hostnameValidation: ClientHostnameValidationConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base64ConfigValue(#[serde(with = "base64")] pub Vec<u8>);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientCaCertificateConfig {
    System,
    CustomPem(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientHostnameValidationConfig {
    AcceptInvalid,
    Hostname(String),
}

//
// Config impls
//

impl Config {
    pub fn from_reader(reader: impl Read) -> Result<Self, failure::Error> {
        Ok(serde_yaml::from_reader(reader)?)
    }
}
