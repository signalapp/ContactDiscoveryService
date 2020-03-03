/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
