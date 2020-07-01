//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod logger;

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use failure::ResultExt;
use futures::prelude::*;
use futures::stream;
use futures::try_ready;
use log::{debug, error, info, log, warn};
use tk_listen::ListenExt;
use tokio::net::TcpListener;

use crate::child;
use crate::counter::*;
use crate::proxy_child::*;
use crate::util;
use crate::util::CommandExt;

const LISTEN_RETRY_DELAY: Duration = Duration::from_secs(5);

pub struct TlsProxyListener {
    bin_path:        PathBuf,
    arguments:       TlsProxyListenerArguments,
    max_connections: usize,
    tcp_listener:    TcpListener,
}

pub enum TlsProxyListenerArguments {
    Config { config_file: PathBuf, key_file: PathBuf },
    NoConfig { ca_file: PathBuf, key_file: PathBuf },
}

//
// TlsProxyListener impls
//

impl TlsProxyListener {
    pub fn new(
        listen_host_port: impl ToSocketAddrs,
        bin_path: PathBuf,
        max_connections: usize,
        arguments: TlsProxyListenerArguments,
    ) -> Result<Self, failure::Error>
    {
        bin_path
            .metadata()
            .with_context(|_| format!("error opening bin file {}", bin_path.display()))?;

        match &arguments {
            TlsProxyListenerArguments::Config { config_file, key_file } => {
                config_file
                    .metadata()
                    .with_context(|_| format!("error opening config file {}", config_file.display()))?;
                key_file
                    .metadata()
                    .with_context(|_| format!("error opening key file {}", key_file.display()))?;
            }
            TlsProxyListenerArguments::NoConfig { ca_file, key_file } => {
                ca_file
                    .metadata()
                    .with_context(|_| format!("error opening ca certificate file {}", ca_file.display()))?;
                key_file
                    .metadata()
                    .with_context(|_| format!("error opening key file {}", key_file.display()))?;
            }
        }

        let listen_addr = util::to_socket_addr(listen_host_port).context("invalid listen address")?;
        let tcp_listener = TcpListener::bind(&listen_addr).with_context(|_| format!("error listening on {}", listen_addr))?;

        Ok(Self {
            bin_path,
            arguments,
            max_connections,
            tcp_listener,
        })
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, tokio::io::Error> {
        self.tcp_listener.local_addr()
    }

    pub fn proxy_to(self, target_address: SocketAddr) -> impl Future<Item = (), Error = failure::Error> {
        self.into_stream()
            .for_each(move |proxy_child: TlsProxyStream| proxy_child.proxy_to(target_address).or_else(|()| Ok(())))
    }

    pub fn into_stream(self) -> impl Stream<Item = TlsProxyStream, Error = failure::Error> {
        let Self {
            bin_path,
            arguments,
            max_connections,
            mut tcp_listener,
        } = self;

        let connection_counter = AtomicCounter::default();

        let tcp_connections = stream::poll_fn(move || Ok(Async::Ready(Some(try_ready!(tcp_listener.poll_accept_std())))));
        let tcp_connections = tcp_connections
            .sleep_on_error(LISTEN_RETRY_DELAY)
            .map_err(|()| failure::format_err!("listen error"));
        let proxy_children = tcp_connections.filter_map(move |(source_stream, source_address): (std::net::TcpStream, SocketAddr)| {
            let connection_count = connection_counter.count();
            if connection_count >= max_connections {
                warn!(
                    "{} => connection dropped due to max connections {}",
                    source_address, connection_count
                );
                return None;
            }
            let counter_guard = connection_counter.inc();

            match Self::spawn_proxy(&bin_path, &arguments, source_stream) {
                Ok(child) => {
                    let child = TlsProxyChild::new(child, source_address);
                    let child_pid = child.pid();

                    let (stdio_stream, stderr_stream) = match child.into_streams() {
                        Ok(child_streams) => child_streams,
                        Err(error) => {
                            info!("{} => error setting up child proxy streams: {}", source_address, error);
                            return None;
                        }
                    };

                    let stderr_logger = Self::log_proxy_stderr(stderr_stream, source_address, child_pid).then(move |_| {
                        drop(counter_guard);
                        Ok(())
                    });
                    tokio::spawn(stderr_logger);

                    Some(stdio_stream.into())
                }
                Err(error) => {
                    error!("{} => error spawning child proxy: {}", source_address, error);
                    None
                }
            }
        });

        proxy_children
    }

    fn log_proxy_stderr(
        stderr_stream: TlsProxyStderrStream,
        source_address: SocketAddr,
        child_pid: u32,
    ) -> impl Future<Item = (), Error = ()>
    {
        let log_target = format!("kbuptlsd-{}", child_pid);
        let logger = stderr_stream.for_each(move |line: String| {
            let (log_level, line) = child::logger::parse_line(&line);
            log!(target: &log_target, log_level, "{} => {}", source_address, line);
            Ok(())
        });
        logger.then(move |result: Result<(), io::Error>| match result {
            Ok(()) => {
                debug!("{} => child process died", source_address);
                Ok(())
            }
            Err(error) => {
                warn!("{} => error reading from child stderr: {}", source_address, error);
                Err(())
            }
        })
    }

    fn spawn_proxy(
        bin_path: &Path,
        arguments: &TlsProxyListenerArguments,
        source_stream: std::net::TcpStream,
    ) -> Result<Child, failure::Error>
    {
        let mut child = Command::new(bin_path);
        child.stdin(std::process::Stdio::piped());
        child.stdout(std::process::Stdio::piped());
        child.stderr(std::process::Stdio::piped());

        child.preserve_fd(&source_stream);

        if log::max_level() >= log::Level::Debug {
            child.arg("--debug");
        }

        child.arg("child");
        match &arguments {
            TlsProxyListenerArguments::Config { config_file, key_file } => {
                child.arg("--config-file").arg(config_file);
                child.arg("--key-file").arg(key_file);
            }
            TlsProxyListenerArguments::NoConfig { ca_file, key_file } => {
                child.arg("--ca-file").arg(ca_file);
                child.arg("--key-file").arg(key_file);
            }
        }
        child.arg("--source-fd").arg(source_stream.as_raw_fd().to_string());

        Ok(child.spawn()?)
    }
}
