//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod auth;
pub mod listener;
pub mod service;

use futures::prelude::*;
use rld_api::entities::*;

use crate::*;

#[cfg_attr(test, mockers_derive::mocked(DiscoveryManagerMock))]
pub trait DiscoveryManager {
    type User;
    fn get_attestation(
        &self,
        enclave_name: String,
        user: &Self::User,
        request: RemoteAttestationRequest,
    ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>;
    fn put_discovery_request(
        &self,
        enclave_name: String,
        user: &Self::User,
        request: DiscoveryRequest,
    ) -> Box<dyn Future<Item = DiscoveryResponse, Error = DiscoveryError> + Send>;
}

#[cfg(test)]
impl<User> Clone for DiscoveryManagerMock<User> {
    fn clone(&self) -> Self {
        use mockers::Mock;
        Self::new(self.mock_id, self.scenario.clone())
    }
}
