//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod logger;
mod proxy;
pub mod seccomp;
pub mod stream;
pub mod tls;
pub mod util;

use std::os::unix::prelude::*;

use failure::ResultExt;
use log::{debug, error, warn};
use nix::errno::Errno;
use nix::poll::*;

use self::proxy::*;
use self::seccomp::*;
use self::stream::*;
use self::tls::*;

pub struct ServerChild {
    tls_acceptor:       TlsAcceptor,
    source_tcp_stream:  ProxyTcpStream,
    target_pipe_stream: ProxyPipeStream,
}

pub struct ClientChild {
    tls_connector:      TlsConnector,
    source_pipe_stream: ProxyPipeStream,
    target_tcp_stream:  ProxyTcpStream,
}

pub type Identity = tls::Identity;

//
// ServerChild impls
//

impl ServerChild {
    pub fn new(
        tls_ca_cert: CaCertificate,
        tls_identity: Identity,
        source_tcp_stream: ProxyTcpStream,
        target_pipe_stream: ProxyPipeStream,
    ) -> Result<Self, failure::Error>
    {
        let tls_acceptor = TlsAcceptor::new(tls_identity, tls_ca_cert).context("error setting up tls acceptor")?;

        Ok(ServerChild {
            tls_acceptor,
            source_tcp_stream,
            target_pipe_stream,
        })
    }

    pub fn run(mut self) -> Result<(), failure::Error> {
        setup_seccomp().context("error setting up seccomp")?;

        match handshake(self.tls_acceptor.accept(self.source_tcp_stream)) {
            Ok(mut source_tls_stream) => {
                let _ignore = proxy(
                    "local target",
                    &mut self.target_pipe_stream,
                    "remote source",
                    &mut source_tls_stream,
                );
                Ok(())
            }
            Err(()) => Ok(()),
        }
    }
}

//
// ClientChild impls
//

impl ClientChild {
    pub fn new(
        tls_hostname: TlsHostname,
        tls_ca_certs: Vec<CaCertificate>,
        tls_identity: Option<Identity>,
        source_pipe_stream: ProxyPipeStream,
        target_tcp_stream: ProxyTcpStream,
    ) -> Result<Self, failure::Error>
    {
        let tls_connector = TlsConnector::new(tls_identity, tls_hostname, tls_ca_certs).context("error setting up tls connector")?;
        Ok(Self {
            tls_connector,
            source_pipe_stream,
            target_tcp_stream,
        })
    }

    pub fn run(mut self) -> Result<(), failure::Error> {
        setup_seccomp().context("error setting up seccomp")?;

        debug!("starting TLS handshake");
        match handshake(self.tls_connector.connect(self.target_tcp_stream)) {
            Ok(mut target_tls_stream) => {
                debug!("finished TLS handshake");
                let _ignore = proxy(
                    "local source",
                    &mut self.source_pipe_stream,
                    "remote target",
                    &mut target_tls_stream,
                );
                Ok(())
            }
            Err(()) => Ok(()),
        }
    }
}

//
// internal
//

fn handshake<T: AsRawFd>(mut accept_result: Result<TlsStream<T>, HandshakeError<T>>) -> Result<TlsStream<T>, ()> {
    loop {
        let (stream, poll_flags) = match accept_result {
            Ok(tls_stream) => return Ok(tls_stream),
            Err(HandshakeError::WantRead(stream)) => (stream, EventFlags::POLLIN),
            Err(HandshakeError::WantWrite(stream)) => (stream, EventFlags::POLLOUT),
            Err(HandshakeError::Failure(error)) => {
                warn!("handshake error: {}", error);
                return Err(());
            }
        };
        let mut poll_fds = [PollFd::new(stream.as_raw_fd(), poll_flags)];

        // XXX handshake timeout
        match poll(&mut poll_fds, -1) {
            Ok(_event_count) => (),
            Err(nix::Error::Sys(Errno::EINTR)) => (),
            Err(error) => {
                error!("error polling sockets: {}", error);
                return Err(());
            }
        }
        accept_result = stream.handshake();
    }
}

fn proxy(
    stream_0_name: &'static str,
    stream_0: &mut ProxyPipeStream,
    stream_1_name: &'static str,
    stream_1: &mut (impl ProxyRead + ProxyWrite + AsRawFd),
) -> Result<(), ()>
{
    let mut buffer_0 = ProxyBuffer::new();
    let mut buffer_1 = ProxyBuffer::new();

    loop {
        let mut stream_0_flags = EventFlags::empty();
        let mut stream_1_flags = EventFlags::empty();

        let buffer_0_flags = buffer_0.proxy(stream_0_name, stream_0, stream_1_name, stream_1)?;
        stream_0_flags |= buffer_0_flags.0;
        stream_1_flags |= buffer_0_flags.1;

        let buffer_1_flags = buffer_1.proxy(stream_1_name, stream_1, stream_0_name, stream_0)?;
        stream_0_flags |= buffer_1_flags.1;
        stream_1_flags |= buffer_1_flags.0;

        if buffer_0.is_closed() && buffer_1.is_closed() {
            break;
        }

        let stream_0_write_fd = stream_0.write_fd().unwrap_or(-1);

        fn new_poll_fd(mut fd: RawFd, flags: EventFlags) -> PollFd {
            if flags.is_empty() {
                fd = -1;
            }
            PollFd::new(fd, flags)
        }
        let mut poll_fds = [
            new_poll_fd(stream_0.read_fd(), stream_0_flags & EventFlags::POLLIN),
            new_poll_fd(stream_0_write_fd, stream_0_flags & EventFlags::POLLOUT),
            new_poll_fd(stream_1.as_raw_fd(), stream_1_flags),
        ];

        debug!("polling: {:?}", &poll_fds);
        match poll(&mut poll_fds, -1) {
            Ok(_event_count) => (),
            Err(nix::Error::Sys(Errno::EINTR)) => continue,
            Err(error) => {
                error!("error polling sockets: {}", error);
                return Err(());
            }
        }
    }
    Ok(())
}

macro_rules! cstr {
    ($str:literal) => {
        std::ffi::CStr::from_bytes_with_nul(concat!($str, "\0").as_bytes()).expect("cstr macro bug")
    };
}

fn setup_seccomp() -> Result<(), failure::Error> {
    configure_openssl_for_seccomp()?;

    let mut seccomp = SeccompContext::new().map_err(|()| failure::format_err!("error creating seccomp context"))?;

    let () = seccomp.allow(cstr!("poll"))?;
    let () = seccomp.allow(cstr!("read"))?;
    let () = seccomp.allow(cstr!("write"))?;
    let () = seccomp.allow(cstr!("shutdown"))?;
    let () = seccomp.allow(cstr!("close"))?;
    let () = seccomp.allow(cstr!("exit"))?;
    let () = seccomp.allow(cstr!("exit_group"))?;
    let () = seccomp.allow(cstr!("sigreturn"))?;
    let () = seccomp.allow(cstr!("munmap"))?;
    let () = seccomp.allow(cstr!("brk"))?;
    let () = seccomp.allow(cstr!("futex"))?;
    let () = seccomp.allow(cstr!("restart_syscall"))?;
    let () = seccomp.allow(cstr!("sched_yield"))?;
    let () = seccomp.allow(cstr!("pause"))?;
    let () = seccomp.allow(cstr!("getpid"))?;
    // XXX allow sigaction/sigprocmask/sigtimedwait/sigaltstack?
    // XXX allow restricted prctl? (used in glibc)

    let () = seccomp.deny_errno(cstr!("openat"), Errno::ENOSYS)?;
    let () = seccomp.deny_errno(cstr!("sigaltstack"), Errno::ENOSYS)?;

    seccomp::configure_panic_hook();
    let () = seccomp.load()?;
    Ok(())
}
