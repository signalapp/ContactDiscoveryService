//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use std::collections::HashMap;

use kbupd_util::base64;
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[serde(transparent)]
pub struct RequestId(#[serde(with = "base64")] pub Vec<u8>);

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct ErrorResponse {
    pub errors: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestationRequest {
    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub clientPublic: [u8; 32],
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestationResponse {
    pub attestations: HashMap<String, RemoteAttestation>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestation {
    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub serverEphemeralPublic: [u8; 32],

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub serverStaticPublic: [u8; 32],

    #[serde(with = "base64")]
    pub quote: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub iv: [u8; 12],

    #[serde(with = "base64")]
    pub ciphertext: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub tag: [u8; 16],

    #[serde(with = "base64")]
    pub signature: Vec<u8>,

    pub certificates: String,

    pub signatureBody: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRequest {
    pub addressCount: u32,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub commitment: [u8; 32],

    #[serde(with = "base64")]
    pub data: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub iv: [u8; 12],

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub mac: [u8; 16],

    pub envelopes: HashMap<String, DiscoveryRequestEnvelope>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRequestEnvelope {
    pub requestId: RequestId,

    #[serde(with = "base64")]
    pub data: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub iv: [u8; 12],

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub mac: [u8; 16],
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryResponse {
    pub requestId: RequestId,

    #[serde(with = "base64")]
    pub data: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub iv: [u8; 12],

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub mac: [u8; 16],
}

impl From<Vec<u8>> for RequestId {
    fn from(vec: Vec<u8>) -> Self {
        RequestId(vec)
    }
}
