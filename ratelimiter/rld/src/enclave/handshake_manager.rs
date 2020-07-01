//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::time::{Duration, Instant};

use futures::prelude::*;
use ias_client::*;
use log::{info, warn};
use tokio::timer;
use try_future::TryFuture;

use crate::intel_client::*;
use crate::metrics::*;
use crate::*;

const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

pub struct HandshakeManager {
    enclave_tx:               EnclaveManagerSender,
    intel_client:             RateLimiterIasClient,
    accept_group_out_of_date: bool,
}

#[derive(Debug, failure::Fail)]
enum RefreshAllError {
    #[fail(display = "stale revocation list")]
    StaleRevocationList,
}

lazy_static::lazy_static! {
    static ref GET_SIGNED_QUOTE_OK_METER:    Meter = METRICS.metric(&metric_name!("get_signed_quote", "ok"));
    static ref GET_SIGNED_QUOTE_ERROR_METER: Meter = METRICS.metric(&metric_name!("get_signed_quote", "error"));
}

fn init_metrics() {
    lazy_static::initialize(&GET_SIGNED_QUOTE_OK_METER);
    lazy_static::initialize(&GET_SIGNED_QUOTE_ERROR_METER);
}

impl HandshakeManager {
    pub fn new(enclave_tx: EnclaveManagerSender, intel_client: RateLimiterIasClient, accept_group_out_of_date: bool) -> Self {
        init_metrics();

        Self {
            enclave_tx,
            intel_client,
            accept_group_out_of_date,
        }
    }

    pub fn fetch_all(self) -> impl Future<Item = Self, Error = failure::Error> + Send + 'static {
        let fetched_sig_rl = self.fetch_sig_rl();
        let enclave_tx = self.enclave_tx.clone();
        let quotes_vec = fetched_sig_rl.and_then(move |()| {
            enclave_tx.call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.get_next_quotes(reply_tx))
        });

        let quotes = quotes_vec
            .map(|quotes: Vec<(String, SgxQuote)>| futures::stream::iter_ok(quotes))
            .flatten_stream();

        let state = quotes.fold(self, |state: Self, (enclave_name, sgx_quote): (String, SgxQuote)| {
            let state = state.fetch(enclave_name, sgx_quote);
            state.map_err(|(_, error): (Self, GetQuoteSignatureError)| error)
        });

        state.from_err()
    }

    fn fetch(
        self,
        enclave_name: String,
        quote: SgxQuote,
    ) -> impl Future<Item = Self, Error = (Self, GetQuoteSignatureError)> + Send + 'static
    {
        let signed_quote = self.intel_client.get_quote_signature(quote.data, self.accept_group_out_of_date);

        let state = signed_quote.then(move |result: Result<SignedQuote, GetQuoteSignatureError>| match result {
            Ok(signed_quote) => {
                GET_SIGNED_QUOTE_OK_METER.mark();
                let _ignore = self
                    .enclave_tx
                    .cast(move |enclave_manager: &mut EnclaveManager| enclave_manager.set_current_quote(enclave_name, signed_quote));
                Ok(self)
            }
            Err(get_signed_quote_error) => {
                GET_SIGNED_QUOTE_ERROR_METER.mark();
                Err((self, get_signed_quote_error))
            }
        });

        state
    }

    fn fetch_sig_rl(&self) -> impl Future<Item = (), Error = failure::Error> + Send + 'static {
        let gid = self
            .enclave_tx
            .call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.get_sgx_gid(reply_tx));

        let intel_client = self.intel_client.clone();
        let sig_rl = gid.and_then(move |gid: u32| intel_client.get_signature_revocation_list(gid));

        let enclave_tx = self.enclave_tx.clone();
        let set_sig_rl = sig_rl.map(move |sig_rl: SignatureRevocationList| {
            let _ignore = enclave_tx.cast(|enclave_manager: &mut EnclaveManager| enclave_manager.set_signature_revocation_list(sig_rl));
        });

        set_sig_rl
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> + Send {
        let interval_timer_stream = timer::Interval::new_interval(REFRESH_INTERVAL).map_err(|error| {
            error!("tokio timer error: {}", error);
        });

        let interval_timer = interval_timer_stream.fold(self, |state: Self, _now: Instant| {
            let refresh_all_result = state.refresh_all();

            let refresh_all_result = refresh_all_result.or_else(|(state, error): (Self, RefreshAllError)| match error {
                RefreshAllError::StaleRevocationList => {
                    info!("fetching new signature revocation list from IAS");
                    let sig_rl = state.fetch_sig_rl();
                    let fetch_result = sig_rl.then(move |sig_rl_result: Result<(), failure::Error>| match sig_rl_result {
                        Ok(()) => state.refresh_all().map_err(|(state, error)| (state, error.into())).into(),
                        Err(error) => TryFuture::from_error((state, error.context("error fetching revocation list from IAS").into())),
                    });
                    fetch_result
                }
            });

            let refresh_all_result = refresh_all_result.or_else(|(state, error): (Self, failure::Error)| -> Result<Self, ()> {
                warn!("error refreshing all quotes: {:?}", error);
                Ok(state)
            });

            refresh_all_result
        });

        interval_timer.map(|_state: Self| {
            error!("tokio timer terminated");
        })
    }

    fn refresh_all(self) -> impl Future<Item = Self, Error = (Self, RefreshAllError)> {
        let quotes_vec = self
            .enclave_tx
            .call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.get_next_quotes(reply_tx));

        let quotes = quotes_vec
            .then(
                |quotes_result: Result<Vec<(String, SgxQuote)>, failure::Error>| match quotes_result {
                    Ok(quotes) => Ok(futures::stream::iter_ok(quotes)),
                    Err(error) => {
                        warn!("error retrieving quotes: {:?}", error);
                        Ok(futures::stream::iter_ok(vec![]))
                    }
                },
            )
            .flatten_stream();

        quotes.fold(self, |state: Self, (enclave_name, sgx_quote): (String, SgxQuote)| {
            state
                .fetch(enclave_name, sgx_quote)
                .then(|fetch_result: Result<Self, (Self, GetQuoteSignatureError)>| {
                    fetch_result.or_else(|(state, error)| match error {
                        GetQuoteSignatureError::QuoteVerificationError(QuoteVerificationError::StaleRevocationList) => {
                            Err((state, RefreshAllError::StaleRevocationList))
                        }
                        error => {
                            warn!("error fetching quote from IAS: {:?}", error);
                            Ok(state)
                        }
                    })
                })
        })
    }
}
