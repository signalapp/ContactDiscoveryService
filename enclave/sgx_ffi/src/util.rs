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

use core::ffi::c_void;
use core::mem;

use super::bindgen_wrapper::dlmallinfo;

pub use super::bindgen_wrapper::{consttime_memequal, memset_s};

pub fn clear(buf: &mut [u8]) {
    let res = unsafe { memset_s(buf.as_ptr() as *mut c_void, buf.len(), 0, buf.len()) };
    assert_eq!(res, 0);
}

pub fn consttime_eq(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> bool {
    let left = left.as_ref();
    let right = right.as_ref();
    if left.len() == right.len() {
        let res = unsafe { consttime_memequal(left.as_ptr() as *const c_void, right.as_ptr() as *const c_void, left.len()) };
        res != 0
    } else {
        false
    }
}

#[derive(Default)]
pub struct SecretValue<T: AsMut<[u8]> + ?Sized>(T);

pub struct MemoryStatus {
    pub footprint_bytes: u32,
    pub used_bytes:      u32,
    pub free_chunks:     u32,
}

pub trait ToUsize {
    fn to_usize(self) -> usize;
}

pub trait ToU64 {
    fn to_u64(self) -> u64;
}

//
// SecretValue impls
//

impl<T: AsMut<[u8]>> SecretValue<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: AsMut<[u8]> + ?Sized> SecretValue<T> {
    pub fn clear(&mut self) {
        clear(self.0.as_mut());
    }

    pub fn clear_to(&mut self, len: usize) {
        if let Some(data) = self.0.as_mut().get_mut(..len) {
            clear(data);
        } else {
            self.clear();
        }
    }

    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> SecretValue<T> {
    pub fn consttime_eq(&self, other: &[u8]) -> bool {
        self::consttime_eq(self.0.as_ref(), other)
    }
}

impl<T: AsMut<[u8]> + Default> SecretValue<T> {
    pub fn into_inner(mut self) -> T {
        mem::replace(&mut self.0, Default::default())
    }
}

impl<T: AsMut<[u8]> + ?Sized> Drop for SecretValue<T> {
    fn drop(&mut self) {
        self.clear();
    }
}

//
// MemoryStatus impls
//

#[allow(clippy::cast_sign_loss)]
impl MemoryStatus {
    pub fn collect() -> Self {
        let mallinfo = unsafe { dlmallinfo() };
        Self {
            footprint_bytes: mallinfo.arena as u32,
            used_bytes:      mallinfo.uordblks as u32,
            free_chunks:     mallinfo.ordblks as u32,
        }
    }
}

//
// ToUsize impls
//

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl ToUsize for u32 {
    fn to_usize(self) -> usize {
        self as usize
    }
}

#[allow(clippy::cast_possible_truncation)]
#[cfg(any(target_pointer_width = "64"))]
impl ToUsize for u64 {
    fn to_usize(self) -> usize {
        self as usize
    }
}

//
// ToU64 impls
//

#[cfg(any(target_pointer_width = "64"))]
impl ToU64 for usize {
    fn to_u64(self) -> u64 {
        self as u64
    }
}
