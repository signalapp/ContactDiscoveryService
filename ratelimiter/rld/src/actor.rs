//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use futures::future;
use futures::prelude::*;
use futures::sync::mpsc;
use futures::sync::oneshot;

type Message<State> = Box<dyn FnOnce(&mut State) + Send>;

pub struct Receiver<State>(mpsc::UnboundedReceiver<Message<State>>);
pub struct Sender<State>(mpsc::UnboundedSender<Message<State>>);

//
// free functions
//

pub fn channel<State>() -> (Sender<State>, Receiver<State>) {
    let (tx, rx) = mpsc::unbounded();
    (Sender(tx), Receiver(rx))
}

pub fn new<State>(state: State) -> (Sender<State>, impl Future<Item = (), Error = ()>) {
    let (tx, rx) = self::channel();
    (tx, rx.enter_loop(state))
}

pub fn spawn<State, Executor>(state: State, runtime: &Executor) -> Result<Sender<State>, failure::Error>
where
    Executor: future::Executor<Box<dyn Future<Item = (), Error = ()> + Send + 'static>>,
    State: Send + 'static,
{
    let (tx, future) = self::new(state);
    runtime
        .execute(Box::new(future))
        .map_err(|error: future::ExecuteError<_>| failure::format_err!("executor error: {:?}", error))?;
    Ok(tx)
}

//
// Receiver impls
//

impl<State> Receiver<State> {
    pub fn enter_loop(self, mut state: State) -> impl Future<Item = (), Error = ()> {
        self.0.for_each(move |fun: Message<State>| {
            fun(&mut state);
            Ok(())
        })
    }
}

impl<State> Stream for Receiver<State> {
    type Error = ();
    type Item = Message<State>;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.0.poll()
    }
}

//
// Sender impls
//

impl<State: 'static> Sender<State> {
    pub fn cast(&self, fun: impl FnOnce(&mut State) + Send + 'static) -> Result<(), ()> {
        self.0.unbounded_send(Box::new(fun)).map_err(|_| ())
    }

    pub fn call<T, E>(
        &self,
        fun: impl FnOnce(&mut State, oneshot::Sender<Result<T, E>>) + Send + 'static,
    ) -> impl Future<Item = T, Error = E> + Send + 'static
    where
        T: Send + 'static,
        E: From<futures::Canceled> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let _ignore = self.0.unbounded_send(Box::new(move |manager: &mut State| fun(manager, tx)));
        rx.from_err().and_then(|result: Result<T, E>| result)
    }

    pub fn sync_call<T, E>(
        &self,
        fun: impl FnOnce(&mut State) -> Result<T, E> + Send + 'static,
    ) -> impl Future<Item = T, Error = E> + Send + 'static
    where
        T: Send + 'static,
        E: From<futures::Canceled> + Send + 'static,
    {
        self.call(move |state: &mut State, reply_tx| {
            let _ignore = reply_tx.send(fun(state));
        })
    }
}

impl<State> Clone for Sender<State> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
