//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;

use log::{debug, info};
use nix::poll::*;

use super::stream::*;

pub struct ProxyBuffer {
    buffer:       Box<[u8; BUFFER_SIZE]>,
    length:       usize,
    position:     usize,
    read_closed:  bool,
    write_closed: bool,
}

const BUFFER_SIZE: usize = 32 * 1024;

//
// ProxyBuffer impls
//

impl ProxyBuffer {
    pub fn new() -> Self {
        Self {
            buffer:       Box::new([0; BUFFER_SIZE]),
            length:       0,
            position:     0,
            read_closed:  false,
            write_closed: false,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.read_closed && self.write_closed
    }

    pub fn proxy(
        &mut self,
        in_name: &'static str,
        in_stream: &mut impl ProxyRead,
        out_name: &'static str,
        out_stream: &mut impl ProxyWrite,
    ) -> Result<(EventFlags, EventFlags), ()>
    {
        while !self.is_closed() {
            match self.proxy_read(in_name, in_stream) {
                Ok(()) => (),
                Err(ProxyStreamError::WantRead) => return Ok((EventFlags::POLLIN, EventFlags::empty())),
                Err(ProxyStreamError::WantWrite) => return Ok((EventFlags::POLLOUT, EventFlags::empty())),
                Err(ProxyStreamError::Io(_)) => return Err(()),
            }
            match self.proxy_write(out_name, out_stream) {
                Ok(()) => (),
                Err(ProxyStreamError::WantRead) => return Ok((EventFlags::empty(), EventFlags::POLLIN)),
                Err(ProxyStreamError::WantWrite) => return Ok((EventFlags::empty(), EventFlags::POLLOUT)),
                Err(ProxyStreamError::Io(_)) => return Err(()),
            }
        }
        Ok((EventFlags::empty(), EventFlags::empty()))
    }

    fn proxy_read(&mut self, in_name: &'static str, in_stream: &mut impl ProxyRead) -> Result<(), ProxyStreamError> {
        loop {
            let read_result = match self.read_from(in_stream) {
                Ok(0) => {
                    info!("connection closed by {}", in_name);
                    self.read_closed = true;
                    Ok(())
                }
                Ok(bytes_read) => {
                    debug!("{} bytes in buffer from {}", bytes_read, in_name);
                    Ok(())
                }
                Err(error @ ProxyStreamError::WantRead) | Err(error @ ProxyStreamError::WantWrite) => Err(error),
                Err(ProxyStreamError::Io(ref error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(ProxyStreamError::Io(error)) => {
                    if error.kind() == io::ErrorKind::UnexpectedEof {
                        info!("connection closed ungracefully by {}: {}", in_name, error);
                    } else {
                        info!("error reading from {}: {}", in_name, error);
                    }
                    Err(ProxyStreamError::Io(error))
                }
            };
            break read_result;
        }
    }

    fn proxy_write(&mut self, out_name: &'static str, out_stream: &mut impl ProxyWrite) -> Result<(), ProxyStreamError> {
        loop {
            let write_result = match self.write_to(out_stream) {
                Ok(wrote_bytes) => {
                    if wrote_bytes != 0 {
                        debug!("wrote {} bytes to {}", wrote_bytes, out_name);
                    }

                    if self.position == self.length {
                        if self.read_closed && !self.write_closed {
                            match out_stream.shutdown() {
                                Ok(()) => {
                                    debug!("shut down connection to {}", out_name);
                                    self.write_closed = true;
                                    Ok(())
                                }
                                Err(error @ ProxyStreamError::WantRead) | Err(error @ ProxyStreamError::WantWrite) => Err(error),
                                Err(ProxyStreamError::Io(ref error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                                Err(ProxyStreamError::Io(error)) => {
                                    info!("error shutting down connection to {}: {}", out_name, error);
                                    Err(ProxyStreamError::Io(error))
                                }
                            }
                        } else {
                            Ok(())
                        }
                    } else {
                        continue;
                    }
                }
                Err(error @ ProxyStreamError::WantRead) | Err(error @ ProxyStreamError::WantWrite) => Err(error),
                Err(ProxyStreamError::Io(ref error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(ProxyStreamError::Io(error)) => {
                    info!("error writing to {}: {}", out_name, error);
                    Err(ProxyStreamError::Io(error))
                }
            };
            break write_result;
        }
    }

    pub fn read_from(&mut self, stream: &mut impl ProxyRead) -> Result<usize, ProxyStreamError> {
        if self.position == self.length {
            self.length = stream.read(&mut self.buffer[..])?;
            self.position = 0;
        } else {
            stream.read(&mut [])?;
        }
        Ok(self.length - self.position)
    }

    pub fn write_to(&mut self, stream: &mut impl ProxyWrite) -> Result<usize, ProxyStreamError> {
        if self.position < self.length {
            let wrote_bytes = stream.write(&mut self.buffer[self.position..self.length])?;
            self.position = self.position.saturating_add(wrote_bytes);
            assert!(self.position <= self.length);
            Ok(wrote_bytes)
        } else {
            Ok(0)
        }
    }
}
