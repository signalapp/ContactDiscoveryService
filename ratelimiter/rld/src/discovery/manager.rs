//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::HashSet;
use std::convert::TryInto;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use futures::future;
use futures::prelude::*;
use futures::sync::oneshot;
use log::warn;
use rld_api::entities::*;

use super::request_manager::*;
use super::*;
use crate::api::auth::signal_user::SignalUser;
use crate::api::DiscoveryManager;
use crate::enclave::error::*;
use crate::enclave::ratelimit_state::*;
use crate::metrics::*;
use crate::util::ToHex;

lazy_static::lazy_static! {
    static ref RATE_LIMITED_ALREADY_EXCEEDED_METER: Meter = METRICS.metric(&metric_name!("rate_limit_already_exceeded"));
}

fn init_metrics() {
    lazy_static::initialize(&RATE_LIMITED_ALREADY_EXCEEDED_METER);
}

pub struct SignalDiscoveryManager<DiscoveryEnclaveTy> {
    enclave_manager:    DiscoveryEnclaveTy,
    discovery_id_key:   Arc<ring::hmac::SigningKey>,
    ratelimit_set_size: u32,
    state_directory:    PathBuf,
    request_manager:    DiscoveryRequestManagerSender,
    ratelimited_set:    Arc<RwLock<HashSet<UserId>>>,
}

impl<DiscoveryEnclaveTy> SignalDiscoveryManager<DiscoveryEnclaveTy> {
    pub fn new(
        enclave_manager: DiscoveryEnclaveTy,
        discovery_id_key: ring::hmac::SigningKey,
        ratelimit_set_size: u32,
        state_directory: PathBuf,
        request_manager: DiscoveryRequestManagerSender,
    ) -> Self
    {
        init_metrics();
        Self {
            enclave_manager,
            discovery_id_key: Arc::new(discovery_id_key),
            ratelimit_set_size,
            state_directory,
            request_manager,
            ratelimited_set: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    fn user_to_user_id(&self, user: &SignalUser) -> UserId {
        let signature = ring::hmac::sign(&self.discovery_id_key, user.username.as_bytes());
        signature.as_ref()[..16].try_into().unwrap_or_else(|_| unreachable!())
    }

    fn user_id_to_path(&self, user_id: &UserId) -> PathBuf {
        let mut directory = PathBuf::from(self.state_directory.clone());
        directory.push(format!(
            "{:02x}/{:02x}/{:02x}/{}",
            &user_id[0],
            &user_id[1],
            &user_id[2],
            ToHex(&user_id[3..])
        ));
        directory
    }

    fn get_ratelimit_state(&self, user_id: &UserId) -> Box<dyn Future<Item = RateLimitState, Error = DiscoveryError> + Send> {
        if let Ok(ratelimited_set) = self.ratelimited_set.read() {
            if ratelimited_set.contains(user_id) {
                warn!("ratelimit already exceeded for id: {:?}", user_id);
                RATE_LIMITED_ALREADY_EXCEEDED_METER.mark();
                return Box::new(future::result::<RateLimitState, DiscoveryError>(Err(
                    DiscoveryError::RateLimitExceeded,
                )));
            }
        } else {
            return Box::new(future::result::<RateLimitState, DiscoveryError>(Err(
                DiscoveryError::RateLimitedSetLockPoisoned("failed to take read lock".to_owned()),
            )));
        }

        let ratelimit_state_path = self.user_id_to_path(user_id);
        let ratelimit_state = RateLimitState::new(self.ratelimit_set_size, ratelimit_state_path);
        Box::new(future::result::<RateLimitState, DiscoveryError>(ratelimit_state))
    }
}

impl<DiscoveryEnclaveTy> DiscoveryManager for SignalDiscoveryManager<DiscoveryEnclaveTy>
where DiscoveryEnclaveTy: DiscoveryEnclave + Send + Clone + 'static
{
    type User = SignalUser;

    fn get_attestation(
        &self,
        enclave_name: String,
        _user: &SignalUser,
        request: RemoteAttestationRequest,
    ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>
    {
        self.enclave_manager.get_attestation(enclave_name, request)
    }

    fn put_discovery_request(
        &self,
        enclave_name: String,
        user: &SignalUser,
        request: DiscoveryRequest,
    ) -> Box<dyn Future<Item = DiscoveryResponse, Error = DiscoveryError> + Send>
    {
        let user_id = self.user_to_user_id(user);
        let request_id = request.envelope.requestId.clone();
        let (tx, rx) = oneshot::channel();

        let maybe_cached_response = self
            .request_manager
            .call(move |request_manager: &mut DiscoveryRequestManager, reply_tx| {
                request_manager.start_request(user_id, request_id, reply_tx)
            });

        let state = self.clone();
        let response_result = maybe_cached_response.and_then(move |maybe_cached_response: Option<DiscoveryResponse>| {
            if let Some(cached_response) = maybe_cached_response {
                return future::Either::A(Ok(cached_response).into_future());
            }

            let request_id = request.envelope.requestId.clone();
            let ratelimit_state = state.get_ratelimit_state(&user_id);
            let ratelimit_result = ratelimit_state.and_then(move |ratelimit_state: RateLimitState| {
                let enclave_response = state
                    .enclave_manager
                    .put_discovery_request(enclave_name, user_id, request, ratelimit_state);
                enclave_response.then(
                    move |response_result: Result<(DiscoveryResponse, RateLimitState), DiscoveryError>| {
                        let response_result = match response_result {
                            Ok((ok_response, ratelimit_state)) => ratelimit_state.store().map(|_| ok_response),
                            Err(err) => match err {
                                DiscoveryError::RateLimitExceeded => match state.ratelimited_set.write() {
                                    Ok(mut ratelimited_set) => {
                                        warn!("marking ratelimit exceeded for id: {:?}", user_id);
                                        ratelimited_set.insert(user_id);
                                        Err(err)
                                    }
                                    Err(_) => Err(DiscoveryError::RateLimitedSetLockPoisoned("failed to take write lock".to_owned())),
                                },
                                _ => Err(err),
                            },
                        };
                        let cache_response_result = response_result.clone();
                        let _ignore = state.request_manager.cast(move |request_manager: &mut DiscoveryRequestManager| {
                            request_manager.finish_request(user_id, request_id, cache_response_result)
                        });
                        response_result
                    },
                )
            });
            future::Either::B(ratelimit_result)
        });
        tokio::spawn(
            response_result.then(move |response_result: Result<DiscoveryResponse, DiscoveryError>| {
                let _ignore = tx.send(response_result);
                Ok(())
            }),
        );

        let response = rx.then(|rx_result: Result<_, futures::Canceled>| rx_result?);
        Box::new(response)
    }
}

impl<DiscoveryEnclaveTy> Clone for SignalDiscoveryManager<DiscoveryEnclaveTy>
where DiscoveryEnclaveTy: DiscoveryEnclave + Clone
{
    fn clone(&self) -> Self {
        Self {
            enclave_manager:    self.enclave_manager.clone(),
            discovery_id_key:   self.discovery_id_key.clone(),
            ratelimit_set_size: self.ratelimit_set_size,
            state_directory:    self.state_directory.clone(),
            request_manager:    self.request_manager.clone(),
            ratelimited_set:    self.ratelimited_set.clone(),
        }
    }
}
