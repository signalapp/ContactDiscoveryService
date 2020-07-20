//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::{hash_map, HashMap, VecDeque};
use std::time::Duration;

use futures::future;
use futures::prelude::*;
use futures::sync::oneshot;
use rld_api::entities::*;
use tokio::timer::delay_queue;
use tokio::timer::delay_queue::DelayQueue;

use crate::enclave::ratelimit_state::*;
use crate::*;

const MAX_PENDING_REQUEST_WAITERS: usize = 5;

pub type DiscoveryRequestManagerSender = actor::Sender<DiscoveryRequestManager>;

pub struct DiscoveryRequestManager {
    requests:    HashMap<UserId, RequestState>,
    expirations: DelayQueue<UserId>,
    request_ttl: Duration,
}

enum RequestState {
    Pending(PendingRequestState),
    Finished(FinishedRequestState),
}

struct PendingRequestState {
    request_id: RequestId,
    expiration: delay_queue::Key,
    waiters:    VecDeque<oneshot::Sender<Result<Option<DiscoveryResponse>, DiscoveryError>>>,
}

struct FinishedRequestState {
    request_id: RequestId,
    expiration: delay_queue::Key,
    result:     Box<Result<DiscoveryResponse, DiscoveryError>>,
}

impl DiscoveryRequestManager {
    pub fn new(request_ttl: Duration) -> Self {
        Self {
            requests: Default::default(),
            expirations: DelayQueue::new(),
            request_ttl,
        }
    }

    pub fn enter_loop(self, mut rx: actor::Receiver<Self>) -> impl Future<Item = Self, Error = ()> {
        let mut maybe_state = Some(self);
        future::poll_fn(move || {
            let state = maybe_state.as_mut().unwrap_or_else(|| panic!("future already yielded"));
            state.poll_expirations().map_err(|timer_error| {
                error!("tokio timer error: {}", timer_error);
            })?;
            while let Some(fun) = futures::try_ready!(rx.poll()) {
                fun(state);
            }
            Ok(Async::Ready(maybe_state.take().unwrap_or_else(|| unreachable!())))
        })
    }

    pub fn start_request(
        &mut self,
        user_id: UserId,
        request_id: RequestId,
        reply_tx: oneshot::Sender<Result<Option<DiscoveryResponse>, DiscoveryError>>,
    )
    {
        match self.requests.entry(user_id) {
            hash_map::Entry::Occupied(mut request_state_entry) => match request_state_entry.get_mut() {
                RequestState::Pending(pending_request_state) if pending_request_state.request_id == request_id => {
                    pending_request_state.add_waiter(reply_tx);
                }
                RequestState::Finished(finished_request_state) if finished_request_state.request_id == request_id => {
                    let reply = finished_request_state.result.clone().map(Some);
                    let _ignore = reply_tx.send(reply);
                }
                request_state => {
                    let expiration = match request_state {
                        RequestState::Pending(pending_request_state) => pending_request_state.expiration.clone(),
                        RequestState::Finished(finished_request_state) => finished_request_state.expiration.clone(),
                    };
                    self.expirations.reset(&expiration, self.request_ttl);

                    let pending_request_state = PendingRequestState::new(request_id, expiration);
                    *request_state = RequestState::Pending(pending_request_state);
                    let _ignore = reply_tx.send(Ok(None));
                }
            },
            hash_map::Entry::Vacant(request_state_entry) => {
                let expiration = self.expirations.insert(user_id, self.request_ttl);
                let pending_request_state = PendingRequestState::new(request_id, expiration);
                request_state_entry.insert(RequestState::Pending(pending_request_state));
                let _ignore = reply_tx.send(Ok(None));
            }
        }
    }

    pub fn finish_request(&mut self, user_id: UserId, request_id: RequestId, result: Result<DiscoveryResponse, DiscoveryError>) {
        let request_state = match self.requests.entry(user_id) {
            hash_map::Entry::Occupied(request_state_entry) => request_state_entry.into_mut(),
            hash_map::Entry::Vacant(_request_state_entry) => return,
        };

        let pending_request_state = match request_state {
            RequestState::Pending(pending_request_state) if pending_request_state.request_id == request_id => pending_request_state,
            _ => return,
        };

        for reply_tx in pending_request_state.waiters.drain(..) {
            let _ignore = reply_tx.send(result.clone().map(Some));
        }

        *request_state = RequestState::Finished(FinishedRequestState {
            request_id,
            expiration: pending_request_state.expiration.clone(),
            result: Box::new(result),
        });
    }

    fn poll_expirations(&mut self) -> Poll<(), tokio::timer::Error> {
        while let Some(expiration) = futures::try_ready!(self.expirations.poll()) {
            self.requests.remove(expiration.get_ref());
        }
        Ok(Async::Ready(()))
    }
}

impl PendingRequestState {
    fn new(request_id: RequestId, expiration: delay_queue::Key) -> Self {
        Self {
            request_id,
            expiration,
            waiters: Default::default(),
        }
    }

    fn add_waiter(&mut self, reply_tx: oneshot::Sender<Result<Option<DiscoveryResponse>, DiscoveryError>>) {
        while self.waiters.len() > MAX_PENDING_REQUEST_WAITERS {
            drop(self.waiters.pop_front());
        }
        self.waiters.push_back(reply_tx);
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use futures::sync::oneshot;
    use rld_api::entities::*;
    use tokio::runtime::current_thread::Runtime;
    use tokio::timer::Delay;

    use super::*;
    use crate::mocks::{rand_array, rand_bytes};

    fn user_id() -> UserId {
        rand_array::<[u8; 16]>().into()
    }

    fn request_id() -> RequestId {
        rand_bytes(vec![0; 32]).into()
    }

    fn response() -> DiscoveryResponse {
        DiscoveryResponse {}
    }

    fn runtime() -> Runtime {
        Runtime::new().unwrap()
    }

    fn sleep(runtime: &mut Runtime, duration: Duration) {
        runtime
            .block_on(Delay::new(Instant::now() + Duration::from_millis(1) + duration))
            .unwrap()
    }

    struct TestDiscoveryRequestManager {
        state: DiscoveryRequestManager,
        tx:    actor::Sender<DiscoveryRequestManager>,
        rx:    actor::Receiver<DiscoveryRequestManager>,
    }

    impl TestDiscoveryRequestManager {
        fn new(state: DiscoveryRequestManager) -> Self {
            let (tx, rx) = actor::channel();
            Self { state, tx, rx }
        }

        fn sender(&self) -> &actor::Sender<DiscoveryRequestManager> {
            &self.tx
        }

        fn flush(self, runtime: &mut Runtime) -> Self {
            drop(self.tx);
            let state = runtime.block_on(self.state.enter_loop(self.rx)).unwrap();
            let (tx, rx) = actor::channel();
            Self { state, tx, rx }
        }
    }

    impl Default for TestDiscoveryRequestManager {
        fn default() -> Self {
            Self::new(DiscoveryRequestManager::new(Duration::from_secs(86400)))
        }
    }

    #[test]
    fn test_expire_request() {
        let mut runtime = runtime();
        let request_ttl = Duration::from_millis(0);
        let request_manager = TestDiscoveryRequestManager::new(DiscoveryRequestManager::new(request_ttl));
        let (user_id, request_id) = (user_id(), request_id());

        let (reply_1_tx, mut reply_1_rx) = oneshot::channel();
        let (reply_2_tx, mut reply_2_rx) = oneshot::channel();
        let (reply_3_tx, mut reply_3_rx) = oneshot::channel();
        let (reply_4_tx, mut reply_4_rx) = oneshot::channel();
        let (reply_5_tx, mut reply_5_rx) = oneshot::channel();

        let request_id_clone1 = request_id.clone();
        request_manager
            .sender()
            .cast(move |request_manager: &mut DiscoveryRequestManager| {
                request_manager.start_request(user_id, request_id_clone1.clone(), reply_1_tx);
                request_manager.start_request(user_id, request_id_clone1.clone(), reply_2_tx);
            })
            .unwrap();

        let request_manager = request_manager.flush(&mut runtime);
        sleep(&mut runtime, request_ttl);

        let request_id_clone2 = request_id.clone();
        request_manager
            .sender()
            .cast(move |request_manager: &mut DiscoveryRequestManager| {
                request_manager.start_request(user_id, request_id_clone2.clone(), reply_3_tx);
            })
            .unwrap();

        let request_manager = request_manager.flush(&mut runtime);
        sleep(&mut runtime, request_ttl);

        request_manager
            .sender()
            .cast(move |request_manager: &mut DiscoveryRequestManager| {
                request_manager.finish_request(user_id, request_id.clone(), Ok(response()));
                request_manager.start_request(user_id, request_id.clone(), reply_4_tx);
                request_manager.start_request(user_id, request_id.clone(), reply_5_tx);
                request_manager.finish_request(user_id, request_id.clone(), Ok(response()));
            })
            .unwrap();

        let request_manager = request_manager.flush(&mut runtime);
        drop(request_manager);

        let reply_1 = reply_1_rx.try_recv().unwrap().unwrap();
        assert!(reply_1.unwrap().is_none());

        assert!(reply_2_rx.try_recv().is_err());

        let reply_3 = reply_3_rx.try_recv().unwrap().unwrap();
        assert!(reply_3.unwrap().is_none());

        let reply_4 = reply_4_rx.try_recv().unwrap().unwrap();
        assert!(reply_4.unwrap().is_none());

        let reply_5 = reply_5_rx.try_recv().unwrap().unwrap();
        assert!(reply_5.unwrap().is_some());
    }

    #[test]
    fn test_replace_request() {
        let mut request_manager = DiscoveryRequestManager::new(Duration::from_secs(86400));
        let user_id = user_id();
        let request_id_1 = request_id();
        let request_id_2 = request_id();

        let (reply_1_tx, mut reply_1_rx) = oneshot::channel();
        let (reply_2_tx, mut reply_2_rx) = oneshot::channel();
        let (reply_3_tx, mut reply_3_rx) = oneshot::channel();

        request_manager.start_request(user_id, request_id_1.clone(), reply_1_tx);
        request_manager.start_request(user_id, request_id_1.clone(), reply_2_tx);
        request_manager.start_request(user_id, request_id_2, reply_3_tx);

        let reply_1 = reply_1_rx.try_recv().unwrap().unwrap();
        assert!(reply_1.unwrap().is_none());

        assert!(reply_2_rx.try_recv().is_err());

        let reply_3 = reply_3_rx.try_recv().unwrap().unwrap();
        assert!(reply_3.unwrap().is_none());
    }

    #[test]
    fn test_finish_request_ok() {
        let mut request_manager = DiscoveryRequestManager::new(Duration::from_secs(86400));
        let user_id = user_id();
        let request_id = request_id();

        let (reply_1_tx, mut reply_1_rx) = oneshot::channel();
        let (reply_2_tx, mut reply_2_rx) = oneshot::channel();
        let (reply_3_tx, mut reply_3_rx) = oneshot::channel();

        request_manager.start_request(user_id, request_id.clone(), reply_1_tx);
        request_manager.start_request(user_id, request_id.clone(), reply_2_tx);
        request_manager.finish_request(user_id, request_id.clone(), Ok(response()));
        request_manager.start_request(user_id, request_id.clone(), reply_3_tx);

        let reply_1 = reply_1_rx.try_recv().unwrap().unwrap();
        assert!(reply_1.unwrap().is_none());

        let reply_2 = reply_2_rx.try_recv().unwrap().unwrap();
        assert!(reply_2.unwrap().is_some());

        let reply_3 = reply_3_rx.try_recv().unwrap().unwrap();
        assert!(reply_3.unwrap().is_some());
    }

    #[test]
    fn test_finish_request_err() {
        let mut request_manager = DiscoveryRequestManager::new(Duration::from_secs(86400));
        let user_id = user_id();
        let request_id = request_id();

        let (reply_1_tx, mut reply_1_rx) = oneshot::channel();
        let (reply_2_tx, mut reply_2_rx) = oneshot::channel();
        let (reply_3_tx, mut reply_3_rx) = oneshot::channel();

        request_manager.start_request(user_id, request_id.clone(), reply_1_tx);
        request_manager.start_request(user_id, request_id.clone(), reply_2_tx);
        request_manager.finish_request(user_id, request_id.clone(), Err(DiscoveryError::RequestCanceled));
        request_manager.start_request(user_id, request_id.clone(), reply_3_tx);

        let reply_1 = reply_1_rx.try_recv().unwrap().unwrap();
        assert!(reply_1.unwrap().is_none());

        let reply_2 = reply_2_rx.try_recv().unwrap().unwrap();
        assert!(reply_2.is_err());

        let reply_3 = reply_3_rx.try_recv().unwrap().unwrap();
        assert!(reply_3.is_err());
    }

    #[test]
    fn test_finish_replaced_request() {
        let mut request_manager = DiscoveryRequestManager::new(Duration::from_secs(86400));
        let user_id = user_id();
        let request_id_1 = request_id();
        let request_id_2 = request_id();

        let (reply_1_tx, mut reply_1_rx) = oneshot::channel();
        let (reply_2_tx, mut reply_2_rx) = oneshot::channel();
        let (reply_3_tx, mut reply_3_rx) = oneshot::channel();
        let (reply_4_tx, mut reply_4_rx) = oneshot::channel();

        request_manager.start_request(user_id, request_id_1.clone(), reply_1_tx);
        request_manager.start_request(user_id, request_id_1.clone(), reply_2_tx);
        request_manager.start_request(user_id, request_id_2.clone(), reply_3_tx);
        request_manager.start_request(user_id, request_id_2.clone(), reply_4_tx);
        request_manager.finish_request(user_id, request_id_1.clone(), Err(DiscoveryError::RequestCanceled));
        request_manager.finish_request(user_id, request_id_2.clone(), Ok(response()));

        let reply_1 = reply_1_rx.try_recv().unwrap().unwrap();
        assert!(reply_1.unwrap().is_none());

        assert!(reply_2_rx.try_recv().err().is_some());

        let reply_3_rx = reply_3_rx.try_recv().unwrap().unwrap();
        assert!(reply_3_rx.unwrap().is_none());

        let reply_4_rx = reply_4_rx.try_recv().unwrap().unwrap();
        assert!(reply_4_rx.unwrap().is_some());
    }

    #[test]
    fn test_replace_finished_request() {
        let mut request_manager = DiscoveryRequestManager::new(Duration::from_secs(86400));
        let user_id = user_id();
        let request_id_1 = request_id();
        let request_id_2 = request_id();

        let (reply_1_tx, mut reply_1_rx) = oneshot::channel();
        let (reply_2_tx, mut reply_2_rx) = oneshot::channel();
        let (reply_3_tx, mut reply_3_rx) = oneshot::channel();

        request_manager.start_request(user_id, request_id_1.clone(), reply_1_tx);
        request_manager.finish_request(user_id, request_id_1.clone(), Err(DiscoveryError::RequestCanceled));
        request_manager.start_request(user_id, request_id_2.clone(), reply_2_tx);
        request_manager.start_request(user_id, request_id_2.clone(), reply_3_tx);
        request_manager.finish_request(user_id, request_id_2.clone(), Ok(response()));

        let reply_1 = reply_1_rx.try_recv().unwrap().unwrap();
        assert!(reply_1.unwrap().is_none());

        let reply_2_rx = reply_2_rx.try_recv().unwrap().unwrap();
        assert!(reply_2_rx.unwrap().is_none());

        let reply_3_rx = reply_3_rx.try_recv().unwrap().unwrap();
        assert!(reply_3_rx.unwrap().is_some());
    }
}
