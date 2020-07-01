//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![no_std]

use core::arch::x86_64::*;
use core::mem::size_of;
use core::u64;

//
// macros
//

macro_rules! static_unreachable {
    () => {{
        #[cfg(not(debug_assertions))]
        {
            extern "C" {
                pub fn __static_unreachable() -> !;
            }
            unsafe { __static_unreachable() };
        }
        #[cfg(debug_assertions)]
        unreachable!()
    }};
}

//
// public API
//

#[no_mangle]
pub extern "C" fn cds_ratelimit_set_add(
    p_slots_data: *mut u8,
    slots_data_size: usize,
    p_query_phones: *const u64,
    query_phones_count: usize,
)
{
    unsafe {
        let mut ratelimit_set = RatelimitSet::new_mut(p_slots_data, slots_data_size);
        let query_phones = core::slice::from_raw_parts(p_query_phones, query_phones_count);
        ratelimit_set.add(query_phones)
    }
}

#[no_mangle]
pub extern "C" fn cds_ratelimit_set_size(p_slots_data: *const u8, slots_data_size: usize) -> u32 {
    unsafe {
        let ratelimit_set = RatelimitSet::new(p_slots_data, slots_data_size);
        ratelimit_set.size()
    }
}

//
// private types
//

struct RatelimitSet<T> {
    data: T,
}

struct RatelimitSetSlot<T>(T);

//
// RatelimitSet impls
//

impl RatelimitSet<&'_ [u8]> {
    unsafe fn new(p_slots_data: *const u8, slots_data_size: usize) -> Self {
        Self {
            data: core::slice::from_raw_parts(p_slots_data, slots_data_size),
        }
    }
}

impl RatelimitSet<&'_ mut [u8]> {
    unsafe fn new_mut(p_slots_data: *mut u8, slots_data_size: usize) -> Self {
        Self {
            data: core::slice::from_raw_parts_mut(p_slots_data, slots_data_size),
        }
    }
}

impl<T> RatelimitSet<T>
where T: AsRef<[u8]> + AsMut<[u8]>
{
    fn slots_mut<'a>(&'a mut self) -> impl Iterator<Item = RatelimitSetSlot<&'a mut [u8]>> + 'a {
        self.data.as_mut().chunks_exact_mut(size_of::<__m256i>()).map(RatelimitSetSlot)
    }

    unsafe fn add(&mut self, query_phones: &[u64]) {
        for query_phone in query_phones {
            let query_phone_block = _mm256_set1_epi64x(*query_phone as i64);
            let mut query_phone_found_block = _mm256_set1_epi64x(0);

            for slot in self.slots() {
                let query_phone_eq_block = _mm256_cmpeq_epi64(query_phone_block, slot.get());
                query_phone_found_block = _mm256_or_si256(query_phone_found_block, query_phone_eq_block);
            }

            let query_phone_found = _mm256_movemask_epi8(query_phone_found_block);
            let mut insert_query_phone_block = _mm256_and_si256(query_phone_block, _mm256_set1_epi8((query_phone_found != 0) as i8 - 1));

            for mut slot in self.slots_mut() {
                slot.set(_mm256_xor_si256(slot.get(), _mm256_set_epi64x(0, 0, 0, u64::MAX as i64)));
                let slot_eq_zero_block = _mm256_cmpeq_epi64(
                    _mm256_set1_epi64x(0),
                    _mm256_or_si256(slot.get(), _mm256_set_epi64x(0, 0, 0, u64::MAX as i64)),
                );
                let slot_eq_zero_mask = _mm256_movemask_epi8(slot_eq_zero_block) as u64;
                let query_phone_inserted = (slot_eq_zero_mask != 0) as u64;
                let insert_phone_mask = slot_eq_zero_mask &
                    !((slot_eq_zero_mask >> (1 * size_of::<u64>())) |
                        (slot_eq_zero_mask >> (2 * size_of::<u64>())) |
                        (slot_eq_zero_mask >> (3 * size_of::<u64>())));
                let insert_phone_mask_pd = _mm256_set_epi64x(
                    ((insert_phone_mask & (1 << 0)) << (63 - 0)) as i64,
                    ((insert_phone_mask & (1 << 7)) << (63 - 7)) as i64,
                    ((insert_phone_mask & (1 << 15)) << (63 - 15)) as i64,
                    ((insert_phone_mask & (1 << 23)) << (63 - 23)) as i64,
                );
                slot.set(_mm256_castpd_si256(_mm256_blendv_pd(
                    _mm256_castsi256_pd(slot.get()),
                    _mm256_castsi256_pd(insert_query_phone_block),
                    _mm256_castsi256_pd(insert_phone_mask_pd),
                )));
                insert_query_phone_block =
                    _mm256_and_si256(insert_query_phone_block, _mm256_set1_epi8((query_phone_inserted != 0) as i8 - 1));
            }
        }
    }
}

impl<T> RatelimitSet<T>
where T: AsRef<[u8]>
{
    fn slots<'a>(&'a self) -> impl Iterator<Item = RatelimitSetSlot<&'a [u8]>> + 'a {
        self.data.as_ref().chunks_exact(size_of::<__m256i>()).map(RatelimitSetSlot)
    }

    unsafe fn size(&self) -> u32 {
        let mut used_slot_count: u32 = 0;
        for slot in self.slots() {
            let slot_eq_zero_block = _mm256_cmpeq_epi64(
                _mm256_set1_epi64x(0),
                _mm256_or_si256(slot.get(), _mm256_set_epi64x(0, 0, 0, u64::MAX as i64)),
            );
            let slot_eq_zero_mask = _mm256_movemask_epi8(slot_eq_zero_block) as u32;
            used_slot_count += (slot_eq_zero_mask >> 0) & 1;
            used_slot_count += (slot_eq_zero_mask >> 8) & 1;
            used_slot_count += (slot_eq_zero_mask >> 16) & 1;
            used_slot_count += (slot_eq_zero_mask >> 24) & 1;
        }
        used_slot_count
    }
}

//
// RatelimitSetSlot
//

impl<T> RatelimitSetSlot<T>
where T: AsRef<[u8]>
{
    fn get(&self) -> __m256i {
        unsafe { _mm256_loadu_si256(self.0.as_ref().as_ptr() as *const __m256i) }
    }
}

impl<T> RatelimitSetSlot<T>
where T: AsMut<[u8]>
{
    fn set(&mut self, value: __m256i) {
        unsafe { _mm256_storeu_si256(self.0.as_mut().as_mut_ptr() as *mut __m256i, value) }
    }
}

//
// panic module
//

mod panic {
    use core::panic::PanicInfo;

    #[inline(always)]
    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        static_unreachable!()
    }
}
