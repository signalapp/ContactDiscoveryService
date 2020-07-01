//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::cell::RefCell;
use std::thread::LocalKey;

use mockers::*;
use rand::distributions::*;
use rand::*;
use rand_chacha::ChaChaRng;

//
// mock extern "C" functions
//

pub fn set<T>(key: &'static LocalKey<RefCell<Option<T>>>, mock: T) {
    key.with(|key| *key.borrow_mut() = Some(mock));
}

pub fn clear<T>(key: &'static LocalKey<RefCell<Option<T>>>) {
    key.with(|key| *key.borrow_mut() = None);
}

pub fn mock_for<T>(key: &'static LocalKey<RefCell<Option<T>>>, scenario: &Scenario) -> <T as Mock>::Handle
where T: Mock {
    let (mock, handle) = scenario.create_mock::<T>();
    set(key, mock);
    handle
}

//
// random mock values
//

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

thread_local! {
    static RAND_STATE: RefCell<ChaChaRng> = RefCell::new(ChaChaRng::from_seed([0; 32]));
}
