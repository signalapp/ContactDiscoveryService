//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#[cfg(feature = "hyper")]
pub mod hyper;

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::prelude::*;
use std::path::PathBuf;
use std::process::Command;

use failure::{format_err, ResultExt};

use crate::config::*;
use crate::proxy_child::TlsProxyChild;
use crate::util::CommandExt;

pub struct TlsClientProxySpawner {
    bin_path:  PathBuf,
    arguments: TlsClientProxyArguments,
}

pub enum TlsClientProxyArguments {
    Config {
        config_file: PathBuf,
        key_file:    Option<PathBuf>,
    },
    NoConfig {
        ca:       TlsClientProxyCaArgument,
        key_file: Option<PathBuf>,
        hostname: TlsClientProxyHostnameArgument,
    },
}

pub enum TlsClientProxyCaArgument {
    System,
    CustomPemFile(PathBuf),
}

pub enum TlsClientProxyHostnameArgument {
    AllowInvalid,
    Hostname(String),
}

//
// TlsClientProxySpawner impls
//

impl TlsClientProxySpawner {
    pub fn new(bin_path: PathBuf, arguments: TlsClientProxyArguments) -> Result<Self, failure::Error> {
        bin_path
            .metadata()
            .with_context(|_| format!("error opening bin file {}", bin_path.display()))?;

        match &arguments {
            TlsClientProxyArguments::Config {
                config_file: config_file_path,
                key_file,
            } => {
                let config_file = fs::File::open(config_file_path)
                    .with_context(|_| format_err!("error opening config file {}", config_file_path.display()))?;
                let config = Config::from_reader(config_file)
                    .with_context(|_| format_err!("error reading config file {}", config_file_path.display()))?;
                let client_config = config
                    .client
                    .ok_or_else(|| format_err!("config file has no client section: {}", config_file_path.display()))?;
                if client_config.clientCertificatePkcs12.is_none() {
                    let key_file = key_file
                        .as_ref()
                        .ok_or_else(|| format_err!("config file has no clientCertificatePkcs12: {}", config_file_path.display()))?;
                    key_file
                        .metadata()
                        .with_context(|_| format!("error opening key file {}", key_file.display()))?;
                }
            }
            TlsClientProxyArguments::NoConfig { ca, key_file, hostname: _ } => {
                match ca {
                    TlsClientProxyCaArgument::System => (),
                    TlsClientProxyCaArgument::CustomPemFile(ca_file) => {
                        ca_file
                            .metadata()
                            .with_context(|_| format!("error opening ca certificate file {}", ca_file.display()))?;
                    }
                }
                if let Some(key_file) = key_file {
                    key_file
                        .metadata()
                        .with_context(|_| format!("error opening key file {}", key_file.display()))?;
                }
            }
        }

        Ok(Self { bin_path, arguments })
    }

    pub fn spawn(&self, target_stream: impl AsRawFd, target_address: SocketAddr) -> Result<TlsProxyChild, io::Error> {
        let mut child = Command::new(&self.bin_path);
        child.stdin(std::process::Stdio::piped());
        child.stdout(std::process::Stdio::piped());
        child.stderr(std::process::Stdio::piped());

        child.preserve_fd(&target_stream);

        if log::max_level() >= log::Level::Debug {
            child.arg("--debug");
        }

        child.arg("client");
        match &self.arguments {
            TlsClientProxyArguments::Config { config_file, key_file } => {
                child.arg("--config-file").arg(config_file);
                if let Some(key_file) = key_file {
                    child.arg("--key-file").arg(key_file);
                }
            }
            TlsClientProxyArguments::NoConfig { ca, key_file, hostname } => {
                match ca {
                    TlsClientProxyCaArgument::System => child.arg("--ca-system"),
                    TlsClientProxyCaArgument::CustomPemFile(ca_file) => child.arg("--ca-file").arg(ca_file),
                };
                if let Some(key_file) = key_file {
                    child.arg("--key-file").arg(key_file);
                }
                match hostname {
                    TlsClientProxyHostnameArgument::AllowInvalid => child.arg("--allow-invalid-target-hostname"),
                    TlsClientProxyHostnameArgument::Hostname(hostname) => child.arg("--target-hostname").arg(hostname),
                };
            }
        }
        child.arg("--target-fd").arg(target_stream.as_raw_fd().to_string());

        let child = child.spawn()?;

        Ok(TlsProxyChild::new(child, target_address))
    }
}
