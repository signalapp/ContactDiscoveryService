/*
 * Copyright (C) 2020 Open Whisper Systems
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
