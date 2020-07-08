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

/// Maintains a set of previously queried phone numbers
///
/// # Overview
///
/// The rate limit set can be visualized as an array of phone numbers,
/// encoded as an unsigned 64-bit integers.
///
/// The rate limit array is first initialized to zero.  The zero value
/// indicates that a location in the rate limit array is available to
/// hold a new number.
///
/// Given a phone number, the rate limit array is scanned looking for
/// a match.  If a match is found, no action is taken. If a match is
/// not found, the new number is added to the first available empty
/// location.
///
/// The "occupancy" of the rate limit array is defined as the count of
/// non-zero locations.
///
/// The rate limit is exceeded when the occupancy exceeds a
/// specified value.
///
/// # Details: Rate Limit State Update Algorithm
///
/// To help mitigate against timing and other "observational" attacks
/// the update algorithm uses constant time and constant memory access
/// techniques.
///
/// ## Background
///
/// The update algorithm replies on Intel AVX2 intrinsics, which
/// operate on 256-bit chunks of data.  Thus the data set can be
/// visualized as an array of "slots", where each slot contains four
/// 64-bit integers:
///
/// | slot | lane 0 | lane 1 | lane 2 | lane 3 |
/// |------+--------+--------+--------+--------|
/// | 0    | u64    | u64    | u64    | u64    |
/// | 1    | u64    | u64    | u64    | u64    |
/// | ..   | u64    | u64    | u64    | u64    |
/// | N-1  | u64    | u64    | u64    | u64    |
///
/// The Intel AVX2 functions operate on a slot's worth of data a time.
///
/// In the algorithm below, the data in lane 0 is always written with
/// all ones, i.e. 0xFFFFFFFFFFFFFFFF.  This ensures that we are
/// always reading/writing every slot of the data.
///
/// Lane 0 is not used to store actual rate limit state.  Only lanes
/// 1, 2, and 3 contain actual phone data.
///
/// ## Reference
///
/// - [Rust Intrinsics API](https://doc.rust-lang.org/core/arch/x86_64/)
/// - [Intel AVX2 Intrinsics](https://software.intel.com/sites/landingpage/IntrinsicsGuide/#techs=AVX2)
///
impl<T> RatelimitSet<T>
where T: AsRef<[u8]> + AsMut<[u8]>
{
    fn slots_mut<'a>(&'a mut self) -> impl Iterator<Item = RatelimitSetSlot<&'a mut [u8]>> + 'a {
        self.data.as_mut().chunks_exact_mut(size_of::<__m256i>()).map(RatelimitSetSlot)
    }

    /// Adds the list of phone numbers to the rate limit state
    ///
    /// # Safety
    ///
    /// This function uses Intel AVX2 intrinsics, which are all marked
    /// as `unsafe` in the core::arch::x86_64 module.
    unsafe fn add(&mut self, query_phones: &[u64]) {
        for query_phone in query_phones {
            // query_phone_block holds a slot's worth of data
            // (256-bits) with all four "lanes" set to the current
            // phone number in question:
            //
            // query_phone_block = | [query_phone] [query_phone] [query_phone] [query_phone] |
            let query_phone_block = _mm256_set1_epi64x(*query_phone as i64);

            // query_phone_found_block is used as an accumulator, initialized to zero.
            let mut query_phone_found_block = _mm256_set1_epi64x(0);

            // constant time -- loop over every slot
            for slot in self.slots() {
                // Compare the current slot to query_phone_block.
                //
                // _mm256_cmpeq_epi64(a, b) - compares the 64-bit
                // lanes of a and b. If a 64-bit lane in a and b are
                // equal, then the corresponding lane in the result is
                // set to all ones, 0xFFFFFFFFFFFFFFFF, otherwise set
                // to zero.  In the examples let's abbreviate
                // 0xFFFFFFFFFFFFFFFF as 0xF~F.
                //
                // If a 64-bit lane in query_phone_block and the
                // current slot are equal, then the corresponding lane
                // in query_phone_eq_block is set to all ones,
                // 0xF~F.
                //
                // For example, say lane 2 in the current slot matched
                // the current query_phone, then query_phone_eq_block
                // would contain: | [0x0] [0x0] [0xF~F] [0x0] |
                let query_phone_eq_block = _mm256_cmpeq_epi64(query_phone_block, slot.get());

                // _mm256_or_si256(a, b) computes the bitwise OR of
                // the arguments.
                //
                // In the case of no match, we are just OR-ing in
                // zeros.  In the case of a match we OR in 0xF~F for
                // the lane that matched.
                //
                // Following the example we get:
                //     query_phone_found_block: | [0x0] [0x0] [0x0  ] [0x0] |
                //        OR-ed with
                //     query_phone_eq_block:    | [0x0] [0x0] [0xF~F] [0x0] |
                //        EQUALS
                //     query_phone_found_block: | [0x0] [0x0] [0xF~F] [0x0] |
                query_phone_found_block = _mm256_or_si256(query_phone_found_block, query_phone_eq_block);
            }

            // When we exit the above loop, the query_phone was either
            // found or not found.  If query_phone is found, then
            // query_phone_found_block contains one lane of all ones
            // (0xF~F) with the rest set to zero.  If the query_phone
            // is not found, then query_phone_found_block contains all
            // zero in all lanes.
            //
            // _mm256_movemask_epi8(a) Creates 32-bit mask from the
            // most significant bit of each 8-bit element in the
            // argument.  This is a reduction operation.
            //
            // Here, query_phone_found is non-zero if we find a match,
            // otherwise zero.
            let query_phone_found = _mm256_movemask_epi8(query_phone_found_block);

            // If the query_phone is not found, insert the phone into
            // the *first* available location (slot, lane).

            // _mm256_set1_epi8(a) - Broadcasts 8-bit integer a to all
            // elements of returned vector.
            //
            // _mm256_and_si256(a, b) - Returns logical 256-bit AND of
            // arguments a and b.

            // Logical AND query_phone_block with either all ones (if
            // not found) or all zeros (if found).
            //
            // Following the example:
            //
            // If query_phone is found {
            //   insert_query_phone_block = | [0x0] [0x0] [0x0] [0x0] |
            // } else {
            //   insert_query_phone_block = | [query_phone] [query_phone] [query_phone] [query_phone] |
            // }
            let mut insert_query_phone_block = _mm256_and_si256(query_phone_block, _mm256_set1_epi8((query_phone_found != 0) as i8 - 1));

            for mut slot in self.slots_mut() {
                // Note: Lane 0 is used as a scratch pad to insure
                // that the entire slot (256-bits) is read from memory
                // and written to memory.  Lane 0 is not used to store
                // actual phone data.  Only lanes 1, 2, and 3 contain
                // phone data.
                //
                // _mm256_set_epi64x(a, b, c, d) - Sets packed 64-bit
                // integers in returned vector with the supplied
                // values.
                //
                // _mm256_xor_si256(a, b) -- Returns logical 256-bit
                // XOR of the arguments.
                //
                // XOR lane 0 of the current slot with [0xF~F].  This
                // guarentees that all 256-bits of the current slot
                // are:
                //   a) read from memory
                //   b) written to memory
                slot.set(_mm256_xor_si256(slot.get(), _mm256_set_epi64x(0, 0, 0, u64::MAX as i64)));

                // Ignoring lane 0, check if the current slot is all
                // zero.
                //
                // Here, lane 0 is OR-ed with all-ones and never
                // equals zero.  Hence the result is guarenteed to
                // have lane 0 set to zero.
                //
                // After the compare, for any source lane containing
                // zero, the result will contain all-ones for that
                // lane.
                //
                // Example 1: source lanes 1, 2, and 3 are zero
                //
                // In this case the result will be:
                //     zero_compare_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
                //        COMPARED WITH
                //     slot, non-zero-lane0: | [0xF~F] [0x0]   [0x0]   [0x0]   |
                //        EQUALS
                //     slot_eq_zero_block:   | [0x0]   [0xF~F] [0xF~F] [0xF~F] |
                //
                // Example 2: source lane 1 occupied.  source lanes 2, and 3 are zero
                //
                // In this case the result will be:
                //     zero_compare_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
                //        COMPARED WITH
                //     slot, non-zero-lane0: | [0xF~F] [stuff] [0x0]   [0x0]   |
                //        EQUALS
                //     slot_eq_zero_block:   | [0x0]   [0x0]   [0xF~F] [0xF~F] |
                //
                // Example 3: source lanes 1, 2, and 3 are all occupied
                //
                // In this case the result will be:
                //     zero_compare_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
                //        COMPARED WITH
                //     slot, non-zero-lane0: | [0xF~F] [stuff] [stuff] [stuff] |
                //        EQUALS
                //     slot_eq_zero_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
                //
                let slot_eq_zero_block = _mm256_cmpeq_epi64(
                    _mm256_set1_epi64x(0),
                    _mm256_or_si256(slot.get(), _mm256_set_epi64x(0, 0, 0, u64::MAX as i64)),
                );

                // _mm256_permute4x64_epi64(a: 256bit, b: i8) --
                // permutes the input vector a in 64-bit chunks,
                // controlled by the b parameter.  Read the Intel
                // Intrinsics docs for how the b parameter works.

                // Permute the lanes of slot_eq_zero_block, with the
                // effect of shifting the contents of each lane to the
                // next higher lane.  In other words, lane 0 goes to
                // lane 1, lane 1 goes to lane 2, lane 2 goes to lane
                // 3, lane 3 is shift out (lost), and lane 0 remains the
                // same.
                //
                // Note: from the previous computation, lane 0 is
                // always guarenteed to be zero.  This also implies
                // that after this permutation, lane 1 will also
                // always be zero.
                //
                // Using the same 3 examples from the last computation.
                //
                // Example 1:
                //
                //   | [0x0]   [0xF~F] [0xF~F] [0xF~F] |
                //       |\       \       \       \
                //       | \       \       \       \
                //       |  \       \       \       \
                //       |   \       \       \       \
                //       |    \       \       \       \
                //       |     \       \       \       \
                //       |      \       \       \       \
                //       |       \       \       \       \
                //       v        \       \       \       \
                //   | [0x0]   [0x0  ] [0xF~F] [0xF~F] |  [LOST]
                //
                // Example 2:
                //
                //   | [0x0]   [0x0  ] [0xF~F] [0xF~F] |
                //       |\       \       \       \
                //       | \       \       \       \
                //       |  \       \       \       \
                //       |   \       \       \       \
                //       |    \       \       \       \
                //       |     \       \       \       \
                //       |      \       \       \       \
                //       |       \       \       \       \
                //       v        \       \       \       \
                //   | [0x0]   [0x0  ] [0x0  ] [0xF~F] |  [LOST]
                //
                // Example 3:
                //
                //   | [0x0]   [0x0  ] [0x0  ] [0x0  ] |
                //       |\       \       \       \
                //       | \       \       \       \
                //       |  \       \       \       \
                //       |   \       \       \       \
                //       |    \       \       \       \
                //       |     \       \       \       \
                //       |      \       \       \       \
                //       |       \       \       \       \
                //       v        \       \       \       \
                //   | [0x0]   [0x0  ] [0x0  ] [0x0  ] |  [LOST]
                //
                let shifted_slot_eq_zero_block = _mm256_permute4x64_epi64(slot_eq_zero_block, 0b1001_0000i32);

                // XOR slot_eq_zero_block with shifted_slot_eq_zero_block
                //
                // Following the 3 examples.
                //
                // Example 1:
                //
                // In this case the result will be:
                //     slot_eq_zero_block:         | [0x0] [0xF~F] [0xF~F] [0xF~F] |
                //        XOR-ed WITH
                //     shifted_slot_eq_zero_block: | [0x0] [0x0  ] [0xF~F] [0xF~F] |
                //        EQUALS
                //     insert_phone_mask_pd:       | [0x0] [0xF~F] [0x0  ] [0x0  ] |
                //
                // Example 2:
                //
                // In this case the result will be:
                //     slot_eq_zero_block:         | [0x0] [0x0] [0xF~F] [0xF~F] |
                //        XOR-ed WITH
                //     shifted_slot_eq_zero_block: | [0x0] [0x0] [0x0  ] [0xF~F] |
                //        EQUALS
                //     insert_phone_mask_pd:       | [0x0] [0x0] [0xF~F] [0x0  ] |
                //
                // Example 3:
                //
                // In this case the result will be:
                //     slot_eq_zero_block:         | [0x0] [0x0] [0x0] [0x0] |
                //        XOR-ed WITH
                //     shifted_slot_eq_zero_block: | [0x0] [0x0] [0x0] [0x0] |
                //        EQUALS
                //     insert_phone_mask_pd:       | [0x0] [0x0] [0x0] [0x0] |
                //
                // The *net* result of all of these examples is that
                // in the case of an available lane, we have a nice
                // AND mask to put data into the *first* available
                // lane.  In the case of no available lanes, the AND
                // mask is all zero.
                let insert_phone_mask_pd = _mm256_xor_si256(slot_eq_zero_block, shifted_slot_eq_zero_block);

                // _mm256_movemask_epi8(a) is a reduction operation
                // described above.
                //
                // insert_phone_mask is non-zero if any lanes in
                // insert_phone_mask_pd are non-zero, i.e. if we are
                // inserting a new phone into this slot.
                let insert_phone_mask = _mm256_movemask_epi8(insert_phone_mask_pd);

                // query_phone_inserted is "1" if we are inserting a
                // phone in this slot and "0" otherwise.
                let query_phone_inserted = (insert_phone_mask != 0) as u64;

                // This one is a bit odd as the core operation is
                // _mm256_blendv_pd(), which is a floating point
                // vector operation for packed 4x64-bit floats.  The
                // operation works at the bit level, so it also works
                // for packed 4x64-bit integers.
                //
                // The real work happens with _mm256_blendv_pd(a, b, c),
                // which "blends" packed double-precision (64-bit)
                // floating-point elements from a and b using c as a
                // mask.
                //
                // If a 64-bit lane in the mask "c" is non-zero, copy
                // the corresponding lane from input argument "b" into
                // the corresponding lane of the result.  Otherwise
                // copy the corresponding lane from input argument "a"
                // into the corresponding lane of the result.
                //
                // _mm256_castsi256_pd(a) and _mm256_castpd_si256(a):
                // These simply "cast" the 4xi64 data to/from 4xf64
                // data. These do no work, just makes the compiler
                // type checker happy.
                //
                // There are two top level cases to consider: was the
                // query_phone found or not?
                //
                // Case 1: query_phone found
                //
                // In this case we should *not* update the rate limit state.
                //
                // As discussed above, insert_query_phone_block is all
                // zero in this case.
                //
                // Returning to the 3 examples:
                //
                // Example 1:
                //   (a) slot:                     | [0xF~F] [0x0]   [0x0]   [0x0] |
                //      BLENDED WITH
                //   (b) insert_query_phone_block: | [0x0]   [0x0]   [0x0]   [0x0] |
                //      USING MASK
                //   (c) insert_phone_mask_pd:     | [0x0]   [0xF~F] [0x0]   [0x0] |
                //                                   [use a] [use b] [use a] [use a]
                //
                //      result                     | [0xF~F] [0x0]   [0x0]   [0x0] |
                //
                //   The result is the slot is unchanged, as desired.
                //
                // Example 2:
                //   (a) slot:                     | [0xF~F] [stuff] [0x0]   [0x0] |
                //      BLENDED WITH
                //   (b) insert_query_phone_block: | [0x0]   [0x0]   [0x0]   [0x0] |
                //      USING MASK
                //   (c) insert_phone_mask_pd:     | [0x0]   [0x0]   [0xF~F] [0x0] |
                //                                   [use a] [use a] [use b] [use a]
                //      result                     | [0xF~F] [stuff] [0x0]   [0x0] |
                //
                //   The result is the slot is unchanged, as desired.
                //
                // Example 3:
                //   (a) slot                      | [0xF~F] [stuff] [stuff] [stuff] |
                //      BLENDED WITH
                //   (b) insert_query_phone_block: | [0x0]   [0x0]   [0x0]   [0x0]   |
                //      USING MASK
                //   (c) insert_phone_mask_pd:     | [0x0]   [0x0]   [0x0]   [0x0]   |
                //                                   [use a] [use a] [use a] [use a]
                //      result                     | [0xF~F] [stuff] [stuff] [stuff] |
                //
                //   The result is the slot is unchanged, as desired.
                //
                // Case 2: query_phone not found
                //
                // In this case we should update the rate limit state
                // if this slot contains an available lane, otherwise
                // this slot should not be updated.
                //
                // As discussed above, insert_query_phone_block has
                // all four lanes set to the query_phone value in this
                // case.
                //
                // Returning to the 3 examples:
                //
                // Example 1:
                //   (a) slot:                     | [0xF~F]       [0x0]         [0x0]         [0x0]         |
                //      BLENDED WITH
                //   (b) insert_query_phone_block: | [query_phone] [query_phone] [query_phone] [query_phone] |
                //      USING MASK
                //   (c) insert_phone_mask_pd:     | [0x0]         [0xF~F]       [0x0]         [0x0]         |
                //                                   [use a]       [use b]       [use a]       [use a]
                //
                //      result                     | [0xF~F]       [query_phone] [0x0]         [0x0] |
                //
                //   The result is the query_phone is inserted into
                //   lane 1 and the other lanes are unchanged, as
                //   desired.
                //
                // Example 2:
                //   (a) slot:                     | [0xF~F]       [stuff]       [0x0]         [0x0]         |
                //      BLENDED WITH
                //   (b) insert_query_phone_block: | [query_phone] [query_phone] [query_phone] [query_phone] |
                //      USING MASK
                //   (c) insert_phone_mask_pd:     | [0x0]         [0x0]         [0xF~F]       [0x0]         |
                //                                   [use a]       [use a]       [use b]       [use a]
                //
                //      result                     | [0xF~F]       [stuff]       [query_phone] [0x0]         |
                //
                //   The result is the query_phone is inserted into
                //   lane 2 and the other lanes are unchanged, as
                //   desired.
                //
                // Example 3:
                //   (a) slot                      | [0xF~F]       [stuff]       [stuff]       [stuff]       |
                //      BLENDED WITH
                //   (b) insert_query_phone_block: | [query_phone] [query_phone] [query_phone] [query_phone] |
                //      USING MASK
                //   (c) insert_phone_mask_pd:     | [0x0]         [0x0]         [0x0]         [0x0]         |
                //                                   [use a]       [use a]       [use a]       [use a]
                //
                //      result                     | [0xF~F]       [stuff]       [stuff]       [stuff]       |
                //
                //   The result is the slot is *unchanged* since all
                //   the lanes were full in this slot, as desired.
                //
                slot.set(_mm256_castpd_si256(_mm256_blendv_pd(
                    _mm256_castsi256_pd(slot.get()),
                    _mm256_castsi256_pd(insert_query_phone_block),
                    _mm256_castsi256_pd(insert_phone_mask_pd),
                )));

                // Update the insert_query_phone_block for the next
                // iteration of the slot loop.  If we updated the rate
                // limit state for this slot, do not update any
                // additional slots.
                //
                // Case 1 - query_phone_inserted == 1 (we inserted query_phone into this slot)
                //
                // In this case we want to disable durther insertion attempts.
                // (query_phone_inserted != 0) as i8 - 1) == 0.
                //
                //   insert_query_phone_block: | [query_phone] [query_phone] [query_phone] [query_phone] |
                //      ANDED with
                //   _mm256_set1_epi8(0):      | [0x0]         [0x0]         [0x0]         [0x0]         |
                //      EQUALS
                //   result:                   | [0x0]         [0x0]         [0x0]         [0x0]         |
                //
                // insert_query_phone_block is now all zero and no further updates will occur.
                //
                // Case 2 - query_phone_inserted == 0 (we did *not* insert query_phone into this slot)
                //
                // In this case we want to continue insertion attempts on subsequent slots.
                // (query_phone_inserted != 0) as i8 - 1) == -1i8 == 0xFF as u8.
                //
                //   insert_query_phone_block: | [query_phone] [query_phone] [query_phone] [query_phone] |
                //      ANDED with
                //   _mm256_set1_epi8(0xFF):   | [0xF~F]       [0xF~F]       [0xF~F]       [0xF~F]       |
                //      EQUALS
                //   result:                   | [query_phone] [query_phone] [query_phone] [query_phone] |
                //
                // insert_query_phone_block is unchanged.
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

    /// Counts the number of used rate limit state locations
    ///
    /// # Safety
    ///
    /// This function uses Intel AVX2 intrinsics, which are all marked
    /// as `unsafe` in the core::arch::x86_64 module.
    unsafe fn size(&self) -> u32 {
        let mut used_slot_count: u32 = 0;
        for slot in self.slots() {
            // Ignoring lane 0, check if the current slot is all
            // zero.
            //
            // Here, lane 0 is OR-ed with all-ones and never
            // equals zero.  Hence the result is guarenteed to
            // have lane 0 set to zero.
            //
            // After the compare, for any source lane containing
            // zero, the result will contain all-ones for that
            // lane.
            //
            // Example 1: source lanes 1, 2, and 3 are zero
            //
            // In this case the result will be:
            //     zero_compare_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
            //        COMPARED WITH
            //     slot, non-zero-lane0: | [0xF~F] [0x0]   [0x0]   [0x0]   |
            //        EQUALS
            //     slot_eq_zero_block:   | [0x0]   [0xF~F] [0xF~F] [0xF~F] |
            //
            // Example 2: source lane 1 occupied.  source lanes 2, and 3 are zero
            //
            // In this case the result will be:
            //     zero_compare_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
            //        COMPARED WITH
            //     slot, non-zero-lane0: | [0xF~F] [stuff] [0x0]   [0x0]   |
            //        EQUALS
            //     slot_eq_zero_block:   | [0x0]   [0x0]   [0xF~F] [0xF~F] |
            //
            // Example 3: source lanes 1, 2, and 3 are all occupied
            //
            // In this case the result will be:
            //     zero_compare_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
            //        COMPARED WITH
            //     slot, non-zero-lane0: | [0xF~F] [stuff] [stuff] [stuff] |
            //        EQUALS
            //     slot_eq_zero_block:   | [0x0]   [0x0]   [0x0]   [0x0]   |
            //
            let slot_eq_zero_block = _mm256_cmpeq_epi64(
                _mm256_set1_epi64x(0),
                _mm256_or_si256(slot.get(), _mm256_set_epi64x(0, 0, 0, u64::MAX as i64)),
            );

            // _mm256_movemask_epi8(a) Creates 32-bit mask from the
            // most significant bit of each 8-bit element in the
            // argument.  This is a reduction operation.
            //
            // In slot_eq_zero_mask, groups of 8 bits are set to one
            // if the corresponding lane in slot_eq_zero_block is
            // non-zero, zero otherwise.
            //
            // Considering the 3 examples.
            //
            // Example 1:
            //
            //   slot_eq_zero_block:   | [0x0] [0xF~F] [0xF~F] [0xF~F] |
            //   slot_eq_zero_mask = !(_mm256_movemask_epi8(slot_eq_zero_block))
            //                     = !0xFF_FF_FF_00
            //                     =  0x00_00_00_FF
            //
            // Example 2:
            //
            //   slot_eq_zero_block:   | [0x0] [0x0] [0xF~F] [0xF~F] |
            //   slot_eq_zero_mask = !(_mm256_movemask_epi8(slot_eq_zero_block))
            //                     = !0xFF_FF_00_00
            //                     =  0x00_00_FF_FF
            //
            // Example 3:
            //
            //   slot_eq_zero_block:   | [0x0] [0x0] [0x0] [0x0] |
            //   slot_eq_zero_mask = !(_mm256_movemask_epi8(slot_eq_zero_block))
            //                     = !0x00_00_00_00
            //                     =  0xFF_FF_FF_FF
            //
            let slot_eq_zero_mask = !(_mm256_movemask_epi8(slot_eq_zero_block) as u32);

            // Skipping lane 0, add up the lanes that were occupied.
            //
            // Considering the 3 examples.
            //
            // Example 1:  slot_eq_zero_mask = 0x00_00_00_FF
            //
            //   used_slot_count = 0
            //
            // Example 2:  slot_eq_zero_mask = 0x00_00_FF_FF
            //
            //   used_slot_count = 1
            //
            // Example 3:  slot_eq_zero_mask = 0xFF_FF_FF_FF
            //
            //   used_slot_count = 3
            //
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
