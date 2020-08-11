//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

// Define just enough types to match the extern C interface.
pub type Phone = u64;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Uuid {
    pub data64: [u64; 2usize],
}

// These externs reside in the external shared library.
extern "C" {
    fn cds_c_hash_lookup(
        in_phones: *const u8,
        in_uuids: *const u8,
        phone_count: usize,
        p_query_phones: *const Phone,
        p_query_phone_results: *mut u8,
        query_phone_count: usize,
    ) -> u32;

    fn cds_ratelimit_set_add(p_slots_data: *mut u8, slots_data_size: usize, p_query_phones: *const u64, query_phones_count: usize);

}

pub fn hash_lookup(in_phones: &[Phone], in_uuids: &[Uuid], query_phones: &[Phone], query_phone_results: &mut [Uuid]) -> u32 {
    unsafe {
        cds_c_hash_lookup(
            in_phones.as_ptr() as *const u8,
            in_uuids.as_ptr() as *const u8,
            in_phones.len(),
            query_phones.as_ptr() as *const Phone,
            query_phone_results.as_ptr() as *mut u8,
            query_phones.len(),
        )
    }
}

pub fn ratelimit_set_add(ratelimit_state_slots_data: &mut [u8], query_phones: &[u64]) {
    unsafe {
        cds_ratelimit_set_add(
            ratelimit_state_slots_data.as_mut_ptr(),
            ratelimit_state_slots_data.len(),
            query_phones.as_ptr(),
            query_phones.len(),
        );
    }
}
