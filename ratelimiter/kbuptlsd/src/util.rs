//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::prelude::*;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use nix::fcntl;
use nix::fcntl::FdFlag;

pub use rustunnel::util::*;

pub trait CommandExt {
    fn preserve_fd(&mut self, fd: &impl AsRawFd);
}

pub fn to_socket_addr(address: impl ToSocketAddrs) -> io::Result<SocketAddr> {
    address
        .to_socket_addrs()?
        .next()
        .ok_or(io::Error::new(io::ErrorKind::Other, "empty address"))
}

impl CommandExt for Command {
    fn preserve_fd(&mut self, fd: &impl AsRawFd) {
        let fd = fd.as_raw_fd();
        unsafe {
            self.pre_exec(move || {
                let fd_flag_bits = convert_nix(fcntl::fcntl(fd, fcntl::F_GETFD))?;
                let mut fd_flags = FdFlag::from_bits(fd_flag_bits).unwrap_or_else(FdFlag::empty);
                fd_flags.remove(FdFlag::FD_CLOEXEC);
                assert_eq!(convert_nix(fcntl::fcntl(fd, fcntl::F_SETFD(fd_flags)))?, 0);
                Ok(())
            });
        }
    }
}
