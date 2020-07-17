//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod config;

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use failure::{format_err, ResultExt};
use futures::prelude::*;
use hyper::client::connect::HttpConnector;
use kbuptlsd::prelude::*;
use nix::sys::signal;
use nix::sys::signal::Signal::*;
use rld_config::metrics::*;
use rld_config::RateLimiterConfig;

use crate::api::auth::signal_user::SignalUserAuthenticator;
use crate::api::listener::ApiListener;
use crate::api::service::*;
use crate::discovery::manager::*;
use crate::discovery::request_manager::*;
use crate::intel_client::*;
use crate::limits::rate_limiter::*;
use crate::logger;
use crate::metrics::{JsonReporter, PeriodicReporter, METRICS};
use crate::*;

const DEFAULT_METRICS_INTERVAL: Duration = Duration::from_secs(60);

const REQUEST_CACHE_TTL: Duration = Duration::from_secs(600);

const PENDING_REQUESTS_TABLE_ORDER: u8 = 15;

pub struct RateLimiterService {
    runtime:               tokio::runtime::Runtime,
    enclave_thread_joiner: Box<dyn Future<Item = Result<(), failure::Error>, Error = Box<dyn std::any::Any + Send + 'static>> + Send>,
    access_logger_guard:   slog_async::AsyncGuard,
}

#[derive(Clone)]
pub struct RateLimiterCommandLineConfig<'a> {
    pub enclave_directory: &'a Path,
    pub config_directory:  &'a Path,
    pub state_directory:   &'a Path,
    pub kbuptlsd_bin_path: &'a Path,
    pub full_hostname:     Option<&'a str>,
}

impl RateLimiterService {
    pub fn start(config: RateLimiterConfig, cmdline_config: RateLimiterCommandLineConfig) -> Result<Self, failure::Error> {
        let mut runtime = tokio::runtime::Builder::new().build().context("error starting tokio runtime")?;
        let mut executor = runtime.executor();

        let enclave_manager_channel = EnclaveManagerChannel::new();
        let enclave_manager_tx = enclave_manager_channel.sender().clone();

        let handshake_manager;

        if !config.attestation.disabled {
            let ias_api_version = match config.attestation.apiVersion {
                Some(api_version) => match api_version.as_ref() {
                    "3" => Some(IasApiVersion::ApiVer3),
                    "4" => Some(IasApiVersion::ApiVer4),
                    _ => {
                        return Err(failure::format_err!(
                            "invalid IAS API version: {}.  Must be '3' or '4'.",
                            api_version
                        ));
                    }
                },
                None => None,
            };

            let ias_url = format!("https://{}/{}", config.attestation.hostName, config.attestation.endPoint).to_owned();
            let intel_client_proxy =
                TlsClientProxySpawner::new(cmdline_config.kbuptlsd_bin_path.to_owned(), TlsClientProxyArguments::NoConfig {
                    ca:       TlsClientProxyCaArgument::System,
                    key_file: None,
                    hostname: TlsClientProxyHostnameArgument::Hostname(config.attestation.hostName.clone()),
                })
                .context("error creating intel attestation tls proxy client")?;
            let new_intel_client = new_ias_client(
                ias_url.as_ref(),
                ias_api_version,
                config.attestation.apiKey.as_ref(),
                intel_client_proxy,
            )
            .context("error creating intel attestation client")?;

            handshake_manager = Some(HandshakeManager::new(
                enclave_manager_tx.clone(),
                new_intel_client.clone(),
                config.attestation.acceptGroupOutOfDate,
            ));
        } else {
            handshake_manager = None;
        }

        let enclave_configs = config.enclaves.clone();
        let (enclave_init_tx, enclave_init_rx) = std::sync::mpsc::channel::<()>();
        let (enclave_join_tx, enclave_join_rx) = futures::sync::oneshot::channel::<util::Never>();

        let enclave_spid = config.attestation.spid;
        let enclave_directory = cmdline_config.enclave_directory.to_owned();
        let enclave_thread = thread::spawn(move || -> Result<(), failure::Error> {
            let mut enclaves = Vec::with_capacity(enclave_configs.len());
            for enclave_config in enclave_configs {
                let enclave_name = enclave_config.mrenclave.clone();
                let enclave_filename = format!("{}.so", &enclave_config.mrenclave);
                let enclave_path = enclave_directory.join(&enclave_filename);
                let timer_tick_interval = Duration::from_millis(30000);

                info!(
                    "starting mrenclave {} with timer tick interval {}ms and {:?}",
                    &enclave_name,
                    timer_tick_interval.as_millis(),
                    &enclave_config
                );

                let mut enclave = (Enclave::new(enclave_name.clone(), &enclave_path.to_string_lossy(), enclave_config, enclave_spid)
                    .with_context(|_| format_err!("error creating enclave {}", &enclave_name)))?;
                enclave
                    .start_ratelimiter(PENDING_REQUESTS_TABLE_ORDER)
                    .with_context(|_| format_err!("error starting ratelimiter in mrenclave {}", &enclave_name))?;

                enclaves.push(enclave);
            }

            enclave_init_tx.send(())?;

            let mut enclave_manager = EnclaveManager::new(enclave_manager_channel, enclaves);
            match enclave_manager.run() {
                Ok(()) => info!("enclave manager stopped upon user request"),
                Err(error) => {
                    error!("fatal enclave error: {}", error);
                    return Err(error.into());
                }
            }

            drop(enclave_join_tx);
            Ok(())
        });

        match enclave_init_rx.recv() {
            Ok(()) => (),
            Err(_) => {
                return Err(enclave_thread.join().unwrap().unwrap_err());
            }
        }

        let handshake_manager = if let Some(handshake_manager) = handshake_manager {
            Some(
                runtime
                    .block_on(handshake_manager.fetch_all())
                    .context("error fetching quotes from IAS")?,
            )
        } else {
            None
        };

        let signal_user_authenticator = Arc::new(SignalUserAuthenticator::new(&config.api.userAuthenticationTokenSharedSecret));

        let api_rate_limiters = SignalApiRateLimiters {
            attestation: actor::spawn(RateLimiter::new("attestation", config.api.limits.attestation.into()), &mut executor)?,
            discovery:   actor::spawn(RateLimiter::new("discovery", config.api.limits.discovery.into()), &mut executor)?,
        };

        let (discovery_request_manager_tx, discovery_request_manager_rx) = actor::channel();
        let discovery_request_manager = DiscoveryRequestManager::new(REQUEST_CACHE_TTL);

        let discovery_id_key = ring::hmac::SigningKey::new(&ring::digest::SHA256, &config.api.discoveryIdSecret);

        match fs::metadata(&cmdline_config.state_directory) {
            Ok(_) => fs::remove_dir_all(&cmdline_config.state_directory)
                .with_context(|_| format!("Unable to remove old state directory: {:?}", cmdline_config.state_directory))?,
            Err(error) => match error.kind() {
                ErrorKind::NotFound => { /* ok */ }
                _ => {
                    return Err(failure::Error::from(error)
                        .context(format!("Unable to stat old state directory: {:?}", cmdline_config.state_directory))
                        .into());
                }
            },
        }

        fs::create_dir_all(&cmdline_config.state_directory)
            .with_context(|_| format!("Unable to create state directory: {:?}", cmdline_config.state_directory))?;

        let discovery_manager = SignalDiscoveryManager::new(
            enclave_manager_tx.clone(),
            discovery_id_key,
            config.api.discoveryRateLimitSetSize,
            cmdline_config.state_directory.to_owned(),
            discovery_request_manager_tx,
        );

        let (access_logger, access_logger_guard) =
            logger::AccessLogger::new_with_guard().with_context(|_| format!("Unable to start syslog access logger:"))?;

        let api_service = SignalApiService::new(
            signal_user_authenticator,
            discovery_manager,
            config.api.denyDiscovery,
            api_rate_limiters,
            access_logger,
        );
        let api_listener = ApiListener::new(&config.api.listenHostPort, api_service).context("error starting api listener")?;

        runtime.spawn(api_listener.into_future());
        runtime.spawn(discovery_request_manager.enter_loop(discovery_request_manager_rx).map(drop));
        if let Some(handshake_manager) = handshake_manager {
            runtime.spawn(handshake_manager.into_future());
        }

        if let Some(metrics_config) = config.metrics {
            for reporter_config in metrics_config.reporters {
                let MetricsReporterConfig::Json(json_reporter_config) = reporter_config;

                let mut reporter_http_connector = HttpConnector::new(1);
                reporter_http_connector.enforce_http(false);

                let reporter_tls_proxy =
                    TlsClientProxySpawner::new(cmdline_config.kbuptlsd_bin_path.to_owned(), TlsClientProxyArguments::NoConfig {
                        ca:       TlsClientProxyCaArgument::System,
                        key_file: None,
                        hostname: TlsClientProxyHostnameArgument::Hostname(json_reporter_config.hostname.to_string()),
                    })
                    .context("error creating metrics json reporter tls proxy client")?;

                let reporter_tls_connector = TlsProxyConnector::new(Arc::new(reporter_tls_proxy), reporter_http_connector);

                let reporter_interval = json_reporter_config
                    .intervalSeconds
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_METRICS_INTERVAL);
                let json_reporter = JsonReporter::new(
                    &json_reporter_config.token,
                    &json_reporter_config.hostname,
                    cmdline_config.full_hostname,
                    reporter_tls_connector,
                )
                .context("error creating metrics json reporter")?;
                let periodic_reporter = PeriodicReporter::new(json_reporter, METRICS.clone(), reporter_interval);
                periodic_reporter.start();
            }
        }

        unix_signal::ignore_signal(SIGPIPE).context("error setting sigaction")?;
        unix_signal::ignore_signal(SIGCHLD).context("error setting sigaction")?;

        let unix_signals = unix_signal::handle_signals(vec![SIGHUP, SIGUSR1, SIGUSR2]);
        let unix_signals = runtime.block_on(unix_signals)?;
        let handled_unix_signals = unix_signals.for_each(|signum: signal::Signal| {
            info!("received unix signal {}", signum);
            Ok(())
        });
        let unix_signal_task = handled_unix_signals.map_err(|error: std::io::Error| {
            error!("error in unix signal handler: {}", error);
        });
        runtime.spawn(unix_signal_task);

        let enclave_thread_joiner = Box::new(enclave_join_rx.then(move |_| enclave_thread.join()));
        Ok(Self {
            runtime,
            enclave_thread_joiner,
            access_logger_guard,
        })
    }

    pub fn join(mut self) {
        match self.runtime.block_on(self.enclave_thread_joiner) {
            Ok(Ok(())) => info!("enclave shutdown"),
            Ok(Err(enclave_error)) => error!("enclave error: {}", enclave_error),
            Err(_join_error) => error!("enclave thread died"),
        }
        drop(self.runtime);
        drop(self.access_logger_guard);
    }
}
