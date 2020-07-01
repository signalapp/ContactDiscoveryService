//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::convert::TryInto;
use std::marker::PhantomData;

use cds_enclave_ffi::sgxsd;
use cds_enclave_ffi::sgxsd::{
    CDSEncryptedMsg, MessageReply, SgxsdAesGcmIv, SgxsdAesGcmMac, SgxsdCurve25519PublicKey, SgxsdError, SgxsdMessageHeader, SgxsdQuote,
    SgxsdRequestNegotiationRequest, SgxsdResult, SgxsdServerCallArgs, SgxsdServerInitArgs, SgxsdServerStateHandle,
};
use futures::sync::oneshot;
use ias_client::*;
use log::{debug, warn};
use rld_api::entities::*;
use rld_config::ratelimiter::RateLimiterEnclaveConfig;
use sgx_sdk_ffi::*;

use crate::enclave::ratelimit_state::*;
use crate::metrics::*;
use crate::*;

pub use cds_enclave_ffi::sgxsd::SgxsdQuote as SgxQuote;

lazy_static::lazy_static! {
    static ref ENCLAVE_SGXSD_RATE_LIMITED_EXCEEDED_METER: Meter = METRICS.metric(&metric_name!("sgxsd_error", "rate_limit_exceeded"));
    static ref ENCLAVE_SGXSD_OTHER_ERROR_METER:           Meter = METRICS.metric(&metric_name!("sgxsd_error", "other_error"));
}

fn init_metrics() {
    lazy_static::initialize(&ENCLAVE_SGXSD_RATE_LIMITED_EXCEEDED_METER);
    lazy_static::initialize(&ENCLAVE_SGXSD_OTHER_ERROR_METER);
    init_ratelimit_state_metrics();
}

pub struct Enclave {
    enclave_name:  String,
    enclave_id:    SgxEnclaveId,
    config:        RateLimiterEnclaveConfig,
    server_handle: SgxsdServerStateHandle,
    sgx_spid:      [u8; 16],
    sgx_sig_rl:    SignatureRevocationList,
    signed_quote:  Option<SignedQuote>,
    _unsend:       PhantomData<*mut u8>,
}

//
// Enclave impls
//

impl Enclave {
    pub fn new(
        enclave_name: String,
        enclave_path: &str,
        config: RateLimiterEnclaveConfig,
        sgx_spid: [u8; 16],
    ) -> Result<Self, EnclaveError>
    {
        init_metrics();

        let enclave_id = sgxsd::sgxsd_create_enclave(enclave_path, config.debug)?;

        Ok(Self {
            enclave_name,
            enclave_id,
            config,
            server_handle: 0,
            sgx_spid,
            sgx_sig_rl: Default::default(),
            signed_quote: Default::default(),
            _unsend: Default::default(),
        })
    }

    pub fn name(&self) -> &str {
        &self.enclave_name
    }

    pub fn start_ratelimiter(&mut self, pending_requests_table_order: u8) -> Result<(), EnclaveError> {
        sgxsd::sgxsd_node_init(self.enclave_id, pending_requests_table_order)?;

        let server_handle: SgxsdServerStateHandle = 0;
        let server_init_args = SgxsdServerInitArgs {
            max_query_phones:     Default::default(),
            max_ratelimit_states: self.config.initialCapacity,
        };

        let result = sgxsd::sgxsd_server_start(self.enclave_id, &server_init_args, server_handle);
        if let Err(error) = result {
            error!("discovery_request(): sgxsd_server_start() error: {}", error.clone());
        }
        result.map_err(|error: SgxsdError| error.into())
    }

    pub fn set_signature_revocation_list(&mut self, sig_rl: SignatureRevocationList) {
        if *self.sgx_sig_rl != *sig_rl {
            info!("new signature revocation list of {} bytes", sig_rl.len());
        }
        self.sgx_sig_rl = sig_rl;
    }

    pub fn get_next_quote(&self) -> Result<SgxsdQuote, EnclaveError> {
        Ok(sgxsd::sgxsd_get_next_quote(self.enclave_id, &self.sgx_spid, &self.sgx_sig_rl)?)
    }

    pub fn set_current_quote(&mut self, signed_quote: Option<SignedQuote>) -> Result<(), EnclaveError> {
        sgxsd::sgxsd_set_current_quote(self.enclave_id)?;
        self.signed_quote = signed_quote;
        Ok(())
    }

    pub fn negotiate_client(&self, request: &RemoteAttestationRequest) -> Result<RemoteAttestationResponse, EnclaveError> {
        let sgxsd_request = SgxsdRequestNegotiationRequest {
            client_pubkey: SgxsdCurve25519PublicKey { x: request.clientPublic },
        };
        let sgxsd_resp = sgxsd::sgxsd_negotiate_request(self.enclave_id, &sgxsd_request)?;
        Ok(RemoteAttestationResponse {
            serverStaticPublic:    sgxsd_resp.server_static_pubkey.x,
            serverEphemeralPublic: sgxsd_resp.server_ephemeral_pubkey.x,

            iv:         sgxsd_resp.encrypted_pending_request_id.iv.data,
            tag:        sgxsd_resp.encrypted_pending_request_id.mac.data,
            ciphertext: sgxsd_resp.encrypted_pending_request_id.data.to_vec(),

            quote:         self
                .signed_quote
                .as_ref()
                .map(|signed_quote| signed_quote.quote.clone())
                .unwrap_or_default(),
            certificates:  self
                .signed_quote
                .as_ref()
                .map(|signed_quote| util::pem::encode("CERTIFICATE", signed_quote.certificates.iter().map(|certificate| &certificate[..])))
                .unwrap_or_default(),
            signature:     self
                .signed_quote
                .as_ref()
                .map(|signed_quote| signed_quote.signature.clone())
                .unwrap_or_default(),
            signatureBody: self
                .signed_quote
                .as_ref()
                .map(|signed_quote| String::from_utf8_lossy(&signed_quote.body).to_string())
                .unwrap_or_default(),
        })
    }

    pub fn discovery_request(
        &mut self,
        user_id: UserId,
        request: &DiscoveryRequest,
        mut ratelimit_state: RateLimitState,
        reply_tx: oneshot::Sender<Result<(DiscoveryResponse, RateLimitState), DiscoveryError>>,
    )
    {
        debug!(
            "discovery_request(): id: {}, address_count: {}, ratelimit_state.len(): {}",
            user_id,
            request.addressCount,
            ratelimit_state.len()
        );

        let mut query_data = request.data.clone();

        let server_call_args = SgxsdServerCallArgs {
            query_phone_count:    request.addressCount,
            ratelimit_state_size: ratelimit_state.len() as u32,
            ratelimit_state_uuid: user_id.0.into(),
            ratelimit_state_data: ratelimit_state.as_mut_ptr(),
            query:                CDSEncryptedMsg {
                iv:   SgxsdAesGcmIv { data: request.iv },
                mac:  SgxsdAesGcmMac { data: request.mac },
                size: query_data.len() as u32,
                data: query_data.as_mut_ptr(),
            },
            query_commitment:     request.commitment,
        };

        let pending_request_bytes = request.envelope.requestId.0.clone();
        let pending_request_id = match pending_request_bytes.try_into() {
            Ok(v) => v,
            Err(_) => {
                let _ignore = reply_tx.send(Err(DiscoveryError::InvalidInput));
                return;
            }
        };

        let msg_header = SgxsdMessageHeader {
            iv: SgxsdAesGcmIv { data: request.envelope.iv },
            mac: SgxsdAesGcmMac {
                data: request.envelope.mac,
            },
            pending_request_id,
        };

        // The reply function is not used by the rate limiter enclave,
        // but is required by sgxsd::sgxsd_serval_call() API.
        let sgxsd_reply_fun = move |_result: SgxsdResult<MessageReply>| {
            debug!("DEBUG: enclave: sgxsd_reply_fun(): callback happened");
        };

        let result = sgxsd::sgxsd_server_call(
            self.enclave_id,
            server_call_args,
            &msg_header,
            &request.envelope.data,
            sgxsd_reply_fun,
            self.server_handle,
        );

        if let Err(error) = result {
            match DiscoveryError::from(error) {
                DiscoveryError::RateLimitExceeded => {
                    warn!("discovery_request(): rate limit exceeded");
                    ENCLAVE_SGXSD_RATE_LIMITED_EXCEEDED_METER.mark();
                }
                _ => {
                    error!("discovery_request(): sgxsd_server_call() error: {}", error.clone());
                    ENCLAVE_SGXSD_OTHER_ERROR_METER.mark();
                }
            }
        }

        let reply = result
            .map(|_| (DiscoveryResponse {}, ratelimit_state))
            .map_err(|error: SgxsdError| error.into());

        let _ignore = reply_tx.send(reply);
    }
}
