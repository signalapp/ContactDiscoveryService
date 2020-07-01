//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::HashMap;
use std::sync::mpsc;

use failure::{Fail, ResultExt};
use futures::prelude::*;
use futures::sync::oneshot;
use ias_client::*;
use rld_api::entities::*;

use crate::enclave::enclave::Enclave;
use crate::enclave::ratelimit_state::*;
use crate::*;

type EnclaveManagerCallback = Box<dyn FnOnce(&mut EnclaveManager) -> Result<(), failure::Error> + Send>;

#[derive(Clone)]
pub struct EnclaveManagerSender(mpsc::Sender<EnclaveManagerCallback>);
impl EnclaveManagerSender {
    pub fn cast<F, FErr>(&self, fun: F) -> Result<(), ()>
    where
        F: FnOnce(&mut EnclaveManager) -> Result<(), FErr> + Send + 'static,
        failure::Error: From<FErr>,
    {
        self.0
            .send(Box::new(move |manager: &mut EnclaveManager| Ok(fun(manager)?)))
            .map_err(|_| ())
    }

    pub fn call<F, FErr, T, E>(&self, fun: F) -> impl Future<Item = T, Error = E>
    where
        T: Send + 'static,
        E: From<futures::Canceled> + Send + 'static,
        F: FnOnce(&mut EnclaveManager, oneshot::Sender<Result<T, E>>) -> Result<(), FErr> + Send + 'static,
        failure::Error: From<FErr>,
    {
        let (tx, rx) = oneshot::channel();
        let _ignore = self.cast(move |manager: &mut EnclaveManager| fun(manager, tx));
        rx.from_err().and_then(|result: Result<T, E>| result)
    }
}

pub struct EnclaveManagerChannel {
    tx: EnclaveManagerSender,
    rx: mpsc::Receiver<EnclaveManagerCallback>,
}
impl EnclaveManagerChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let tx = EnclaveManagerSender(tx);
        Self { tx, rx }
    }

    pub fn sender(&self) -> &EnclaveManagerSender {
        &self.tx
    }
}

pub struct EnclaveManager {
    channel:  EnclaveManagerChannel,
    stopped:  bool,
    enclaves: HashMap<String, Enclave>,
}

impl EnclaveManager {
    pub fn new(channel: EnclaveManagerChannel, enclaves: impl IntoIterator<Item = Enclave>) -> Self {
        Self {
            channel,
            stopped: false,
            enclaves: enclaves
                .into_iter()
                .map(|enclave: Enclave| (enclave.name().to_string(), enclave))
                .collect(),
        }
    }

    pub fn run(&mut self) -> Result<(), failure::Error> {
        self.stopped = false;
        while let Ok(fun) = self.channel.rx.recv() {
            fun(self)?;
            if self.stopped {
                break;
            }
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), failure::Error> {
        self.stopped = true;
        Ok(())
    }

    pub fn get_next_quotes(&self, reply_tx: oneshot::Sender<Result<Vec<(String, SgxQuote)>, failure::Error>>) -> Result<(), EnclaveError> {
        let mut quotes: Vec<(String, SgxQuote)> = Vec::with_capacity(self.enclaves.len());
        for (enclave_name, enclave) in self.enclaves.iter() {
            let quote = match enclave.get_next_quote() {
                Ok(quote) => quote,
                Err(error) => {
                    let context = error.clone().context(format!("error fetching quote for enclave {}", enclave_name));
                    let _ignore = reply_tx.send(Err(context.into()));
                    return Err(error);
                }
            };
            quotes.push((enclave_name.clone(), quote));
        }
        let _ignore = reply_tx.send(Ok(quotes));
        Ok(())
    }

    pub fn set_current_quote(&mut self, enclave_name: String, signed_quote: SignedQuote) -> Result<(), EnclaveError> {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            enclave.set_current_quote(Some(signed_quote))
        } else {
            Ok(())
        }
    }

    pub fn remote_attestation(
        &mut self,
        enclave_name: String,
        request: RemoteAttestationRequest,
        reply_tx: oneshot::Sender<Result<RemoteAttestationResponse, RemoteAttestationError>>,
    ) -> Result<(), EnclaveError>
    {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            let result = enclave.negotiate_client(&request);
            if let Err(error) = &result {
                // XXX stop on some enclave errors here
                if let DiscoveryError::EnclaveError(_) = DiscoveryError::from(error.clone()) {
                    error!("remote attestation error: {}", error);
                }
            }
            let _ignore = reply_tx.send(result.map_err(|error| error.into()));
            Ok(())
        } else {
            let _ignore = reply_tx.send(Err(RemoteAttestationError::EnclaveNotFound));
            Ok(())
        }
    }

    pub fn discovery(
        &mut self,
        enclave_name: String,
        user_id: UserId,
        request: DiscoveryRequest,
        ratelimit_state: RateLimitState,
        reply_tx: oneshot::Sender<Result<(DiscoveryResponse, RateLimitState), DiscoveryError>>,
    ) -> Result<(), EnclaveError>
    {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            enclave.discovery_request(user_id, &request, ratelimit_state, reply_tx);
        } else {
            let _ignore = reply_tx.send(Err(DiscoveryError::EnclaveNotFound));
        }
        Ok(())
    }

    pub fn get_sgx_gid(&mut self, reply_tx: oneshot::Sender<Result<u32, failure::Error>>) -> Result<(), EnclaveError> {
        let gid_result = sgx_sdk_ffi::get_gid().context("error fetching sgx gid");
        let _ignore = reply_tx.send(gid_result.map_err(failure::Error::from));
        Ok(())
    }

    pub fn set_signature_revocation_list(&mut self, sig_rl: SignatureRevocationList) -> Result<(), EnclaveError> {
        for (_enclave_name, enclave) in &mut self.enclaves {
            enclave.set_signature_revocation_list(sig_rl.clone());
        }
        Ok(())
    }
}

impl discovery::DiscoveryEnclave for EnclaveManagerSender {
    fn get_attestation(
        &self,
        enclave_name: String,
        request: RemoteAttestationRequest,
    ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>
    {
        let reply = self.call(move |manager: &mut EnclaveManager, reply_tx| manager.remote_attestation(enclave_name, request, reply_tx));
        Box::new(reply)
    }

    fn put_discovery_request(
        &self,
        enclave_name: String,
        user_id: UserId,
        request: DiscoveryRequest,
        ratelimit_state: RateLimitState,
    ) -> Box<dyn Future<Item = (DiscoveryResponse, RateLimitState), Error = DiscoveryError> + Send>
    {
        let reply = self.call(move |manager: &mut EnclaveManager, reply_tx| {
            manager.discovery(enclave_name, user_id, request, ratelimit_state, reply_tx)
        });
        Box::new(reply)
    }
}
