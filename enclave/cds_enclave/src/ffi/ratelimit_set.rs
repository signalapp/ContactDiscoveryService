//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use super::bindgen_wrapper::{cds_ratelimit_set_add, cds_ratelimit_set_size};

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

pub fn ratelimit_set_size(ratelimit_state_slots_data: &[u8]) -> u32 {
    unsafe { cds_ratelimit_set_size(ratelimit_state_slots_data.as_ptr(), ratelimit_state_slots_data.len()) }
}
