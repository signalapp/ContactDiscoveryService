//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;
use std::io::prelude::*;
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

use nix::unistd;

use crate::util;

pub struct ProxyTcpStream {
    fd: RawFd,
}

pub struct ProxyPipeStream {
    read_fd:  RawFd,
    write_fd: Option<RawFd>,
}

pub trait ProxyRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyStreamError>;
}
pub trait ProxyWrite {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ProxyStreamError>;
    fn shutdown(&mut self) -> Result<(), ProxyStreamError>;
}

#[derive(Debug)]
pub enum ProxyStreamError {
    WantRead,
    WantWrite,
    Io(io::Error),
}

//
// ProxyTcpStream impls
//

impl ProxyTcpStream {
    pub fn from_std(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_nonblocking(true)?;
        Ok(Self { fd: stream.into_raw_fd() })
    }
}

impl Read for ProxyTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        <&Self>::read(&mut &*self, buf)
    }
}
impl Write for ProxyTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        <&Self>::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        <&Self>::flush(&mut &*self)
    }
}

impl Read for &'_ ProxyTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        util::convert_nix(unistd::read(self.fd, buf))
    }
}

impl Write for &'_ ProxyTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        util::convert_nix(unistd::write(self.fd, buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for ProxyTcpStream {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for ProxyTcpStream {
    fn drop(&mut self) {
        let _ignore = unistd::close(self.fd);
    }
}

//
// ProxyPipeStream
//

impl ProxyPipeStream {
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Self> {
        util::set_nonblocking(read_fd)?;
        util::set_nonblocking(write_fd)?;
        Ok(Self {
            read_fd,
            write_fd: Some(write_fd),
        })
    }

    pub fn stdio() -> io::Result<Self> {
        let stdin = Box::leak(Box::new(io::stdin()));
        let _stdin_lock = Box::leak(Box::new(stdin.lock()));
        let stdout = Box::leak(Box::new(io::stdout()));
        let _stdout_lock = Box::leak(Box::new(stdout.lock()));

        Self::new(libc::STDIN_FILENO, libc::STDOUT_FILENO)
    }

    pub fn read_fd(&self) -> RawFd {
        self.read_fd
    }

    pub fn write_fd(&self) -> Option<RawFd> {
        self.write_fd
    }
}

impl Read for ProxyPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        <&Self>::read(&mut &*self, buf)
    }
}
impl Write for ProxyPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        <&Self>::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        <&Self>::flush(&mut &*self)
    }
}

impl Read for &'_ ProxyPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        util::convert_nix(unistd::read(self.read_fd, buf))
    }
}

impl Write for &'_ ProxyPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_fd {
            Some(write_fd) => util::convert_nix(unistd::write(write_fd, buf)),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ProxyRead for ProxyPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyStreamError> {
        <&Self as Read>::read(&mut &*self, buf).map_err(|error: io::Error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                ProxyStreamError::WantRead
            } else {
                ProxyStreamError::Io(error)
            }
        })
    }
}

impl ProxyWrite for ProxyPipeStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ProxyStreamError> {
        <&Self as Write>::write(&mut &*self, buf).map_err(|error: io::Error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                ProxyStreamError::WantWrite
            } else {
                ProxyStreamError::Io(error)
            }
        })
    }

    fn shutdown(&mut self) -> Result<(), ProxyStreamError> {
        if let Some(write_fd) = self.write_fd.take() {
            util::convert_nix(unistd::close(write_fd)).map_err(ProxyStreamError::Io)
        } else {
            Ok(())
        }
    }
}

impl Drop for ProxyPipeStream {
    fn drop(&mut self) {
        if let Some(write_fd) = self.write_fd {
            let _ignore = unistd::close(write_fd);
        }
        let _ignore = unistd::close(self.read_fd);
    }
}
