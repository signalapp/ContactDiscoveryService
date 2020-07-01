//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod manager;
pub mod request_manager;

use futures::prelude::*;
use rld_api::entities::*;

use crate::enclave::error::*;
use crate::enclave::ratelimit_state::*;

pub trait DiscoveryEnclave: Send {
    fn get_attestation(
        &self,
        enclave_name: String,
        request: RemoteAttestationRequest,
    ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>;
    fn put_discovery_request(
        &self,
        enclave_name: String,
        user_id: UserId,
        request: DiscoveryRequest,
        ratelimit_state: RateLimitState,
    ) -> Box<dyn Future<Item = (DiscoveryResponse, RateLimitState), Error = DiscoveryError> + Send>;
}
