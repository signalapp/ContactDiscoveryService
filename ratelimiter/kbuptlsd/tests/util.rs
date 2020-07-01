//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(dead_code, unused_macros)]

use std::cell::*;
use std::io::prelude::*;

use failure::ResultExt;
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

thread_local! {
    pub static RAND: RefCell<ChaChaRng> = RefCell::new(SeedableRng::seed_from_u64(0));
}

macro_rules! error_line {
    () => {
        concat!(module_path!(), ":", line!())
    };
}

pub fn assert_stream_closed(mut tcp_stream: impl Read) -> Result<(), failure::Error> {
    let mut buf = [0; 128];
    match tcp_stream.read(&mut buf[..]).context("error reading from socket")? {
        0 => Ok(()),
        n => Err(failure::format_err!(
            "socket not closed, read {} bytes: {}",
            n,
            String::from_utf8_lossy(&buf[..])
        )),
    }
}

pub fn assert_stream_open(mut tcp_stream: impl Read + Write) -> Result<(), failure::Error> {
    let rand_id = RAND.with(|rand| rand.borrow_mut().next_u64());
    let message = format!("{:016x} it works!\n", rand_id).into_bytes();
    let mut buffer = vec![0; message.len()];

    tcp_stream.write_all(&message).context("error writing to socket")?;
    let () = tcp_stream.read_exact(&mut buffer).context("error reading from socket")?;
    if buffer == message {
        Ok(())
    } else {
        Err(failure::format_err!(
            "mock client output doesnt match: {} != {}",
            String::from_utf8_lossy(&buffer),
            String::from_utf8_lossy(&message)
        ))
    }
}
