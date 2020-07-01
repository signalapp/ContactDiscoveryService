//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::sync::*;

use ::hyper::client::connect::{Connect, Connected, Destination};
use futures::prelude::*;
use futures::try_ready;
use log::{debug, log, warn};
use tokio::net::TcpStream;

use super::*;
use crate::child;
use crate::proxy_child::*;

pub struct TlsProxyConnector<T> {
    spawner:   Arc<TlsClientProxySpawner>,
    connector: T,
}

pub struct TlsProxyConnecting<T: Connect> {
    spawner: Arc<TlsClientProxySpawner>,
    connect: T::Future,
}

impl<T> TlsProxyConnector<T> {
    pub fn new(spawner: Arc<TlsClientProxySpawner>, connector: T) -> Self {
        Self { spawner, connector }
    }
}

impl<T> Connect for TlsProxyConnector<T>
where
    T: Connect<Transport = TcpStream>,
    T::Future: Send,
    io::Error: From<<T::Future as Future>::Error>,
{
    type Error = io::Error;
    type Future = TlsProxyConnecting<T>;
    type Transport = TlsProxyStream;

    fn connect(&self, dst: Destination) -> Self::Future {
        Self::Future {
            spawner: Arc::clone(&self.spawner),
            connect: self.connector.connect(dst),
        }
    }
}

impl<T> Future for TlsProxyConnecting<T>
where
    T: Connect<Transport = TcpStream>,
    io::Error: From<T::Error>,
{
    type Error = io::Error;
    type Item = (TlsProxyStream, Connected);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (tcp_stream, _info) = try_ready!(self.connect.poll());
        let peer_addr = tcp_stream.peer_addr()?;
        let (stdio, stderr) = self.spawner.spawn(tcp_stream, peer_addr)?.into_streams()?;

        tokio::spawn(log_proxy_stderr(stderr, peer_addr));

        Ok(Async::Ready((stdio, Connected::new())))
    }
}

fn log_proxy_stderr(stderr_stream: TlsProxyStderrStream, address: SocketAddr) -> impl Future<Item = (), Error = ()> {
    let logger = stderr_stream.for_each(move |line: String| {
        let (mut log_level, line) = child::logger::parse_line(&line);
        // we don't want noisy INFO logs for hyper
        if log_level == log::Level::Info {
            log_level = log::Level::Debug;
        }
        log!(target: "kbuptlsd::child", log_level, "{} => {}", address, line);
        Ok(())
    });
    logger.then(move |result: Result<(), io::Error>| match result {
        Ok(()) => {
            debug!("{} => child process died", address);
            Ok(())
        }
        Err(error) => {
            warn!("{} => error reading from child stderr: {}", address, error);
            Err(())
        }
    })
}
