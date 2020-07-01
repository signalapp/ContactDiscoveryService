//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::cell::*;
use std::fmt;

use bytes::Bytes;
use futures::future;
use futures::prelude::*;
use http::header::HeaderValue;
use rand::distributions::{Distribution, Standard};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

thread_local! {
    static RAND_STATE: RefCell<ChaChaRng> = RefCell::new(ChaChaRng::from_seed([0; 32]));
}

pub fn rand_array<T>() -> T
where T: AsMut<[u8]> + Default {
    rand_bytes(T::default())
}
pub fn rand_bytes<T>(mut buf: T) -> T
where T: AsMut<[u8]> {
    read_rand(buf.as_mut());
    buf
}
pub fn rand<T>() -> T
where Standard: Distribution<T> {
    RAND_STATE.with(|rand| rand.borrow_mut().gen())
}
pub fn read_rand(buf: &mut [u8]) {
    RAND_STATE.with(|rand| rand.borrow_mut().fill_bytes(buf));
}

pub fn basic_auth(username: impl fmt::Display, password: impl fmt::Display) -> HeaderValue {
    let auth = format!("{}:{}", username, password);
    let value = format!("Basic {}", base64::encode(&auth));
    HeaderValue::from_str(&value).unwrap()
}

pub struct AsyncPipe {
    tx:       futures::sync::mpsc::UnboundedSender<Bytes>,
    rx:       futures::sync::mpsc::UnboundedReceiver<Bytes>,
    read_buf: Option<Bytes>,
}
impl AsyncPipe {
    pub fn new() -> (Self, Self) {
        let (tx1, rx1) = futures::sync::mpsc::unbounded();
        let (tx2, rx2) = futures::sync::mpsc::unbounded();
        (
            Self {
                tx:       tx1,
                rx:       rx2,
                read_buf: Default::default(),
            },
            Self {
                tx:       tx2,
                rx:       rx1,
                read_buf: Default::default(),
            },
        )
    }
}
impl std::io::Read for AsyncPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_buf = if let Some(read_buf) = self.read_buf.take() {
            read_buf
        } else {
            match self.rx.poll() {
                Ok(Async::Ready(Some(data))) => data,
                Ok(Async::Ready(None)) => return Ok(0),
                Ok(Async::NotReady) => return Err(std::io::ErrorKind::WouldBlock.into()),
                Err(()) => return Err(std::io::ErrorKind::BrokenPipe.into()),
            }
        };
        let read_len = buf.len().min(read_buf.len());
        buf[..read_len].copy_from_slice(&read_buf.split_to(read_len)[..]);
        if !read_buf.is_empty() {
            self.read_buf = Some(read_buf);
        }
        Ok(read_len)
    }
}
impl tokio::io::AsyncRead for AsyncPipe {}
impl std::io::Write for AsyncPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            Ok(0)
        } else {
            match self.tx.unbounded_send(buf.into()) {
                Ok(()) => Ok(buf.len()),
                Err(_) => Err(std::io::ErrorKind::BrokenPipe.into()),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl tokio::io::AsyncWrite for AsyncPipe {
    fn shutdown(&mut self) -> Poll<(), std::io::Error> {
        Ok(Async::Ready(()))
    }
}

pub struct AsyncPipeConnector {
    tx: futures::sync::mpsc::UnboundedSender<AsyncPipe>,
}

pub struct AsyncPipeIncoming {
    rx: futures::sync::mpsc::UnboundedReceiver<AsyncPipe>,
}

impl AsyncPipeConnector {
    pub fn new() -> (Self, AsyncPipeIncoming) {
        let (tx, rx) = futures::sync::mpsc::unbounded();
        (Self { tx }, AsyncPipeIncoming { rx })
    }
}

impl hyper::client::connect::Connect for AsyncPipeConnector {
    type Error = failure::Error;
    type Future = future::FutureResult<(Self::Transport, hyper::client::connect::Connected), Self::Error>;
    type Transport = AsyncPipe;

    fn connect(&self, _dst: hyper::client::connect::Destination) -> Self::Future {
        let (pipe1, pipe2) = AsyncPipe::new();
        match self.tx.unbounded_send(pipe1) {
            Ok(()) => Ok((pipe2, hyper::client::connect::Connected::new())).into_future(),
            Err(_) => Err(failure::format_err!("async pipe connector closed")).into_future(),
        }
    }
}

impl Stream for AsyncPipeIncoming {
    type Error = failure::Error;
    type Item = AsyncPipe;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.rx.poll() {
            Ok(async_result) => Ok(async_result),
            Err(()) => Ok(Async::Ready(None)),
        }
    }
}
