//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::os::unix::prelude::*;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout};

use futures::prelude::*;
use log::{debug, info};
use mio::unix::EventedFd;
use tokio::codec::{FramedRead, LinesCodec};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::reactor::PollEvented2;

use crate::util;

pub struct TlsProxyChild {
    child:   Child,
    address: SocketAddr,
}

pub struct TlsProxyStream {
    stdin:   TlsProxyStdioAsync<ChildStdin>,
    stdout:  TlsProxyStdioAsync<ChildStdout>,
    address: SocketAddr,
}

pub type TlsProxyStderrStream = FramedRead<TlsProxyStdioAsync<ChildStderr>, LinesCodec>;

pub struct TlsProxyStdioAsync<T: AsRawFd> {
    stdio: Option<PollEvented2<TlsProxyStdioEvented<T>>>,
}

struct TlsProxyStdioEvented<T> {
    stdio: T,
}

//
// TlsProxyChild impls
//

impl TlsProxyChild {
    pub(crate) fn new(child: Child, address: SocketAddr) -> Self {
        Self { child, address }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn into_streams(self) -> Result<(TlsProxyStream, TlsProxyStderrStream), io::Error> {
        let child_stdin = self.child.stdin.ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stdin"))?;
        let child_stdout = self
            .child
            .stdout
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stdout"))?;
        let child_stderr = self
            .child
            .stderr
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stderr"))?;
        let stdio_stream = TlsProxyStream {
            stdin:   TlsProxyStdioAsync::new(child_stdin)?,
            stdout:  TlsProxyStdioAsync::new(child_stdout)?,
            address: self.address,
        };
        let child_stderr = TlsProxyStdioAsync::new(child_stderr)?;
        let stderr_stream = FramedRead::new(child_stderr, LinesCodec::new());
        Ok((stdio_stream, stderr_stream))
    }
}

//
// TlsProxyStream impls
//

impl TlsProxyStream {
    pub fn peer_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn proxy_to(self, target_address: SocketAddr) -> impl Future<Item = (), Error = ()> {
        let address = self.address;

        let target_tcp_stream = tokio::net::TcpStream::connect(&target_address).map_err(move |error: io::Error| {
            info!("{} => error connecting to target {}: {}", address, target_address, error);
        });

        let proxied = target_tcp_stream.map(move |target_tcp_stream: tokio::net::TcpStream| {
            info!("{} => connection established to target {}", address, target_address);

            let (target_tcp_stream_rx, target_tcp_stream_tx) = target_tcp_stream.split();

            let proxied_stdin = tokio::io::copy(target_tcp_stream_rx, self.stdin).then(move |result: io::Result<_>| {
                match result {
                    Ok(_) => info!("{} => connection closed by target", address),
                    Err(error) => info!("{} => error proxying target -> source: {}", address, error),
                }
                Ok(())
            });

            let proxied_stdout = tokio::io::copy(self.stdout, target_tcp_stream_tx).map_err(move |error: io::Error| {
                info!("{} => error proxying source -> target: {}", address, error);
            });
            let proxied_stdout = proxied_stdout.and_then(move |(_, _, target_tcp_stream_tx)| {
                info!("{} => connection closed by source", address);

                tokio::io::shutdown(target_tcp_stream_tx).map_err(move |error: io::Error| {
                    info!("{} => error shutting down target: {}", address, error);
                })
            });
            let proxied_stdout = proxied_stdout.map(move |_| {
                debug!("{} => shut down target", address);
            });

            tokio::spawn(proxied_stdin);
            tokio::spawn(proxied_stdout);
        });

        proxied
    }
}

impl Read for TlsProxyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stdout.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.stdout.read_vectored(bufs)
    }
}

impl Write for TlsProxyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdin.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.stdin.write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdin.flush()
    }
}

impl AsyncRead for TlsProxyStream {}

impl AsyncWrite for TlsProxyStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.stdin.shutdown()
    }
}

//
// TlsProxyStdioAsync impls
//

impl<T: AsRawFd> TlsProxyStdioAsync<T> {
    fn new(stdio: T) -> Result<Self, io::Error> {
        util::set_nonblocking(stdio.as_raw_fd())?;
        Ok(Self {
            stdio: Some(PollEvented2::new(TlsProxyStdioEvented { stdio })),
        })
    }
}

impl<T: Read + AsRawFd> Read for TlsProxyStdioAsync<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.stdio {
            Some(stdio) => stdio.read(buf),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match &mut self.stdio {
            Some(stdio) => stdio.read_vectored(bufs),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }
}

impl<T: Write + AsRawFd> Write for TlsProxyStdioAsync<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.stdio {
            Some(stdio) => stdio.write(buf),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match &mut self.stdio {
            Some(stdio) => stdio.write_vectored(bufs),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stdio {
            Some(stdio) => stdio.flush(),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }
}

impl<T: Read + AsRawFd> AsyncRead for TlsProxyStdioAsync<T> {}

impl<T: Write + AsRawFd> AsyncWrite for TlsProxyStdioAsync<T> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.stdio = None;
        Ok(Async::Ready(()))
    }
}

//
// TlsProxyStdioEvented impls
//

impl<T: Read> Read for TlsProxyStdioEvented<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stdio.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.stdio.read_vectored(bufs)
    }
}

impl<T: Write> Write for TlsProxyStdioEvented<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdio.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.stdio.write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdio.flush()
    }
}

impl<T: AsRawFd> mio::Evented for TlsProxyStdioEvented<T> {
    fn register(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt) -> io::Result<()> {
        EventedFd(&self.stdio.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt) -> io::Result<()> {
        EventedFd(&self.stdio.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.stdio.as_raw_fd()).deregister(poll)
    }
}
