//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use core::num::NonZeroU128;
use core::{u32, u8};

use sgx_ffi::sgx::*;
use sgx_ffi::util::memset_s;

use super::bindgen_wrapper::{
    cds_hash_lookup, phone_t, uuid_t, HashSlot, HashSlotResult, CDS_HASH_LOOKUP_ERROR_HASH_TABLE_OVERFLOW,
    CDS_HASH_LOOKUP_ERROR_INVALID_PARAMETER, CDS_HASH_LOOKUP_ERROR_LAST, CDS_HASH_LOOKUP_ERROR_RDRAND, CDS_HASH_LOOKUP_SUCCESS,
    CDS_MAX_HASH_TABLE_ORDER,
};

pub use super::bindgen_wrapper::{phone_t as Phone, uuid_t as Uuid};

pub const MAX_HASH_TABLE_ORDER: u32 = CDS_MAX_HASH_TABLE_ORDER;
pub const MAX_HASH_TABLE_SIZE: usize = 1 << MAX_HASH_TABLE_ORDER;

#[no_mangle]
pub extern "C" fn cds_c_hash_lookup(
    in_phones: *const u8,
    in_uuids: *const u8,
    phone_count: usize,
    p_query_phones: *const phone_t,
    p_query_phone_results: *mut u8,
    query_phone_count: usize,
) -> u32
{
    unsafe {
        let query_phones = core::slice::from_raw_parts(p_query_phones, query_phone_count);
        let query_phone_results = core::slice::from_raw_parts_mut(p_query_phone_results, query_phone_count * size_of::<uuid_t>());
        match hash_lookup(in_phones, in_uuids, phone_count, query_phones, query_phone_results) {
            Ok(()) => 0,
            Err(err) => err,
        }
    }
}

pub unsafe fn hash_lookup(
    in_phones: *const u8,
    in_uuids: *const u8,
    phone_count: usize,
    query_phones: &[phone_t],
    query_phone_results: &mut [u8],
) -> Result<(), SgxStatus>
{
    // calculate hash table size = query_phone_count rounded up to the nearest power of 2
    let hash_table_slot_count = match query_phones.len().checked_next_power_of_two() {
        Some(hash_table_slot_count @ 0..=MAX_HASH_TABLE_SIZE) => hash_table_slot_count,
        Some(_) | None => return Err(SGX_ERROR_INVALID_PARAMETER),
    };

    // validate hash table size
    if query_phones.is_empty() {
        return Ok(());
    }

    if query_phone_results.len() != query_phones.len().saturating_mul(size_of::<uuid_t>()) {
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // write dummy values to result byte array first, so both true and false force a cache line flush
    slice_memset_s(query_phone_results, u8::MAX);

    // fill hash table with zeroes to force a cache line flush on write below
    let mut hash_slots: Vec<HashSlot> = new_vec_memset_s(hash_table_slot_count, 0u8);
    let mut hash_slot_results: Vec<HashSlotResult> = new_vec_memset_s(hash_table_slot_count, 0u8);

    const CDS_HASH_LOOKUP_ERROR_FIRST_UNDEF: u32 = CDS_HASH_LOOKUP_ERROR_LAST + 1;

    for _ in 0..128 {
        match cds_hash_lookup(
            in_phones as *const phone_t,
            in_uuids as *const uuid_t,
            phone_count,
            query_phones.as_ptr(),
            query_phone_results.as_mut_ptr(),
            query_phones.len().min(query_phone_results.len() / size_of::<uuid_t>()),
            hash_slots.as_mut_ptr(),
            hash_slot_results.as_mut_ptr(),
            hash_slots.len().min(hash_slot_results.len()),
        ) {
            (CDS_HASH_LOOKUP_SUCCESS) => return Ok(()),
            (CDS_HASH_LOOKUP_ERROR_INVALID_PARAMETER) => return Err(SGX_ERROR_UNEXPECTED),
            (CDS_HASH_LOOKUP_ERROR_RDRAND) => return Err(SGX_ERROR_UNEXPECTED),
            (CDS_HASH_LOOKUP_ERROR_HASH_TABLE_OVERFLOW) => debug_assert!(false, "hash table overflow"),
            (CDS_HASH_LOOKUP_ERROR_FIRST_UNDEF..=u32::MAX) => return Err(SGX_ERROR_UNEXPECTED),
        }
    }
    Err(SGX_ERROR_UNEXPECTED)
}

//
// Uuid impls
//

impl From<Uuid> for Option<NonZeroU128> {
    fn from(from: Uuid) -> Self {
        let mut uuid_data = [0; 16];
        uuid_data[..8].copy_from_slice(&from.data64[0].to_ne_bytes());
        uuid_data[8..].copy_from_slice(&from.data64[1].to_ne_bytes());
        NonZeroU128::new(u128::from_ne_bytes(uuid_data))
    }
}

//
// HashSlot impls
//

impl Clone for HashSlot {
    fn clone(&self) -> Self {
        Self { blocks: self.blocks }
    }
}

impl Copy for HashSlot {}

//
// HashSlot impls
//

impl Clone for HashSlotResult {
    fn clone(&self) -> Self {
        Self { blocks: self.blocks }
    }
}

impl Copy for HashSlotResult {}

//
// helpers
//

/// safety: T must be valid after setting its storage bytes to val
unsafe fn slice_memset_s<T>(slice: &mut [T], val: u8) {
    let size = slice.len() * size_of::<T>();
    assert_eq!(0, memset_s(slice.as_mut_ptr() as *mut c_void, size, val.into(), size));
}

/// safety: T must be valid after setting its storage bytes to val
unsafe fn new_vec_memset_s<T>(capacity: usize, val: u8) -> Vec<T> {
    let mut vec = Vec::with_capacity(capacity);
    let size = capacity * size_of::<T>();
    assert_eq!(0, memset_s(vec.as_mut_ptr() as *mut c_void, size, val.into(), size));
    vec.set_len(capacity);
    vec
}

#[cfg(test)]
mod test {
    use super::*;

    use std::convert::TryInto;
    use std::{i64, u64};

    use rand::*;
    use rand_chacha::ChaChaRng;

    struct TestData {
        in_phones:        Vec<Phone>,
        in_uuids:         Vec<Uuid>,
        query_phones:     Vec<Phone>,
        expected_results: Vec<Uuid>,
    }

    impl TestData {
        pub const IN_PHONE_COUNT: usize = 1_000_000;
        pub const QUERY_PHONE_COUNT: usize = 2048;

        pub fn new(seed: [u8; 32]) -> Self {
            let mut rand = ChaChaRng::from_seed(seed);
            let phones_iter = (0..Self::IN_PHONE_COUNT).into_iter();
            let in_phones: Vec<Phone> = phones_iter.clone().map(|_| rand.gen_range(2u64, i64::MAX as u64)).collect();
            let in_uuids: Vec<Uuid> = phones_iter.map(|_| Uuid { data64: rand.gen() }).collect();

            let mut query_phones = Vec::with_capacity(Self::QUERY_PHONE_COUNT);
            let mut expected_results = Vec::with_capacity(Self::QUERY_PHONE_COUNT);
            for _ in 0..Self::QUERY_PHONE_COUNT {
                let rand_idx = rand.gen::<usize>() % (in_phones.len() * 2);
                if rand_idx < in_phones.len() {
                    query_phones.push(in_phones[rand_idx]);
                    expected_results.push(in_uuids[rand_idx]);
                } else {
                    query_phones.push(1);
                    expected_results.push(Uuid { data64: [0, 0] });
                }
            }

            Self {
                in_phones,
                in_uuids,
                query_phones,
                expected_results,
            }
        }

        pub fn in_phone_count(&self) -> usize {
            self.in_phones.len().min(self.in_uuids.len())
        }

        pub fn hash_lookup(&self, in_phone_count: Option<usize>, query_phones: &[Phone]) -> Result<Vec<Uuid>, SgxStatus> {
            let in_phone_count = in_phone_count.unwrap_or(self.in_phone_count());
            test_hash_lookup(&self.in_phones[..in_phone_count], &self.in_uuids[..in_phone_count], query_phones)
        }
    }

    fn test_hash_lookup(in_phones: &[Phone], in_uuids: &[Uuid], query_phones: &[Phone]) -> Result<Vec<Uuid>, SgxStatus> {
        let mut query_phone_results_data: Vec<u8> = vec![0; query_phones.len() * size_of::<Uuid>()];
        assert_eq!(in_phones.len(), in_uuids.len());
        unsafe {
            hash_lookup(
                in_phones.as_ptr() as *const u8,
                in_uuids.as_ptr() as *const u8,
                in_phones.len().min(in_uuids.len()),
                query_phones,
                &mut query_phone_results_data,
            )?;
        }
        let query_phone_results = query_phone_results_data
            .chunks(size_of::<Uuid>())
            .map(|uuid_data: &[u8]| Uuid {
                data64: [
                    u64::from_ne_bytes(uuid_data[..8].try_into().unwrap()),
                    u64::from_ne_bytes(uuid_data[8..].try_into().unwrap()),
                ],
            })
            .collect();
        Ok(query_phone_results)
    }

    lazy_static::lazy_static! {
        static ref TEST_DATA: TestData = TestData::new([0; 32]);
    }

    #[test]
    fn cds_hash_lookup_batch_too_large() {
        assert_eq!(
            TEST_DATA.hash_lookup(None, &vec![0; MAX_HASH_TABLE_SIZE + 1]).unwrap_err(),
            SGX_ERROR_INVALID_PARAMETER
        );
    }

    #[test]
    fn cds_hash_lookup_many_duplicates() {
        let query_phones: Vec<Phone> = std::iter::repeat(TEST_DATA.query_phones[0])
            .take(TestData::QUERY_PHONE_COUNT)
            .collect();
        TEST_DATA
            .hash_lookup(None, &query_phones)
            .unwrap()
            .into_iter()
            .for_each(|uuid: Uuid| assert_eq!(uuid, TEST_DATA.expected_results[0]));
    }

    fn cds_hash_lookup_small(use_in_phones: bool) {
        let query_phone_count = 32;
        let mut query_phones = Vec::with_capacity(query_phone_count);
        let mut expected_results = Vec::with_capacity(query_phone_count);
        for (query_phone, expected_result) in TEST_DATA.query_phones.iter().zip(&TEST_DATA.expected_results) {
            let query_phone_present = expected_result != &Uuid::default();
            if query_phone_present == use_in_phones {
                query_phones.push(*query_phone);
                expected_results.push(*expected_result);
            }
        }
        assert_eq!(TEST_DATA.hash_lookup(None, &query_phones[..]).unwrap(), expected_results,);
    }

    #[test]
    fn cds_hash_lookup_small_all_in_phones() {
        cds_hash_lookup_small(true);
    }

    #[test]
    fn cds_hash_lookup_small_no_in_phones() {
        cds_hash_lookup_small(false);
    }

    #[test]
    fn cds_hash_lookup_small_random() {
        for query_phone_count in 0..=25 {
            assert_eq!(
                TEST_DATA.hash_lookup(None, &TEST_DATA.query_phones[..query_phone_count]).unwrap()[..],
                TEST_DATA.expected_results[..query_phone_count],
            );
        }
    }

    #[test]
    fn cds_hash_lookup_large() {
        assert_eq!(
            TEST_DATA.hash_lookup(None, &TEST_DATA.query_phones).unwrap()[..],
            TEST_DATA.expected_results[..],
        );
    }
}
