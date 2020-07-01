//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt;

use base64;
use serde::Deserializer;

pub fn decode(encoded: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    let space_regex = regex::bytes::Regex::new(r"[ \t\r\n]").unwrap();
    let base64_data = space_regex.replace_all(encoded, &b""[..]);
    let config = base64::Config::new(base64::CharacterSet::Standard, true);
    base64::decode_config(&base64_data, config)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserializer.deserialize_bytes(Base64Visitor)
}

//
// Base64Visitor impls
//

struct Base64Visitor;

impl<'de> serde::de::Visitor<'de> for Base64Visitor {
    type Value = Vec<u8>;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("a base64-encoded string")
    }

    fn visit_bytes<E>(self, base64: &[u8]) -> Result<Self::Value, E>
    where E: serde::de::Error {
        decode(base64).map_err(|error| E::custom(error.to_string()))
    }

    fn visit_str<E>(self, base64: &str) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_bytes(base64.as_bytes())
    }
}
