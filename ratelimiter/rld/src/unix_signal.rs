//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use futures::prelude::*;
use futures::stream::Fuse;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet};

pub struct MergeSignals {
    signals: Vec<Fuse<tokio_signal::unix::Signal>>,
}

pub fn ignore_signal(signum: nix::sys::signal::Signal) -> nix::Result<()> {
    let ignore_sigaction = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    unsafe { sigaction(signum, &ignore_sigaction) }?;
    Ok(())
}

pub fn handle_signals(
    signums: impl IntoIterator<Item = nix::sys::signal::Signal>,
) -> impl Future<Item = MergeSignals, Error = std::io::Error> {
    let signals = signums.into_iter().map(move |signum: nix::sys::signal::Signal| {
        let signal = tokio_signal::unix::Signal::with_handle(signum as i32, &Default::default());
        signal.map(|signal: tokio_signal::unix::Signal| signal.fuse())
    });
    let merged = futures::future::join_all(signals).map(move |signals: Vec<Fuse<tokio_signal::unix::Signal>>| MergeSignals { signals });

    merged
}

impl Stream for MergeSignals {
    type Error = std::io::Error;
    type Item = nix::sys::signal::Signal;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut not_ready = false;
        for signal in &mut self.signals {
            match signal.poll()? {
                Async::Ready(Some(signum)) => match nix::sys::signal::Signal::from_c_int(signum) {
                    Ok(signum) => return Ok(Some(signum).into()),
                    Err(_) => (),
                },
                Async::Ready(None) => (),
                Async::NotReady => not_ready = true,
            }
        }
        if not_ready { Ok(Async::NotReady) } else { Ok(None.into()) }
    }
}
