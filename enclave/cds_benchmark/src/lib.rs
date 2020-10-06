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
