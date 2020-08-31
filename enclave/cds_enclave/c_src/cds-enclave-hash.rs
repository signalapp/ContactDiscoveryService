//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![no_std]
#![allow(non_camel_case_types)]

use core::arch::x86_64::*;
use core::mem::size_of;
use core::u64;

use self::hash_key::HashKey;
use self::in_phones_uuids::InPhonesUuids;

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

pub const CDS_HASH_LOOKUP_SUCCESS: u32 = 0;
pub const CDS_HASH_LOOKUP_ERROR_INVALID_PARAMETER: u32 = 1;
pub const CDS_HASH_LOOKUP_ERROR_RDRAND: u32 = 2;
pub const CDS_HASH_LOOKUP_ERROR_HASH_TABLE_OVERFLOW: u32 = 3;
pub const CDS_HASH_LOOKUP_ERROR_LAST: u32 = 3;

pub type phone_t = u64;
pub type uuid_t = uuid;

#[derive(Default)]
#[repr(C)]
pub struct uuid {
    data64: [u64; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HashSlot {
    blocks: [__m256i; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HashSlotResult {
    blocks: [[__m256i; 2]; 4],
}

#[repr(u32)]
enum CdsHashLookupError {
    InvalidParameter = CDS_HASH_LOOKUP_ERROR_INVALID_PARAMETER,
    RdRand = CDS_HASH_LOOKUP_ERROR_RDRAND,
    HashTableOverflow = CDS_HASH_LOOKUP_ERROR_HASH_TABLE_OVERFLOW,
}

#[no_mangle]
pub extern "C" fn cds_hash_lookup(
    p_in_phones: *const phone_t,
    p_in_uuids: *const uuid_t,
    in_phone_count: usize,
    p_ab_phones: *const phone_t,
    p_ab_phone_results: *mut u8,
    ab_phone_count: usize,
    p_hash_slots: *mut HashSlot,
    p_hash_slot_results: *mut HashSlotResult,
    hash_slots_count: usize,
) -> u32 {
    unsafe {
        let in_phones_uuids = InPhonesUuids::new(p_in_phones, p_in_uuids, in_phone_count);
        let ab_phones = core::slice::from_raw_parts(p_ab_phones, ab_phone_count);
        let ab_phone_results = core::slice::from_raw_parts_mut(p_ab_phone_results, ab_phone_count * size_of::<Uuid>());
        let hash_slots = core::slice::from_raw_parts_mut(p_hash_slots, hash_slots_count);
        let hash_slot_results = core::slice::from_raw_parts_mut(p_hash_slot_results, hash_slots_count);
        let res = hash_lookup(in_phones_uuids, ab_phones, ab_phone_results, hash_slots, hash_slot_results);
        _mm256_zeroall();
        match res {
            Ok(()) => 0,
            Err(error) => error as u32,
        }
    }
}

//
// private types
//

const CHAIN_BLOCK_COUNT: usize = 4;
const CHAIN_BLOCK_PHONE_COUNT: usize = 32 / size_of::<Phone>();
const CHAIN_PHONE_COUNT: HashSlotIdx = (CHAIN_BLOCK_COUNT * CHAIN_BLOCK_PHONE_COUNT) as HashSlotIdx;
const CACHE_LINE_SIZE: usize = 32;

const UINT64_MAX: i64 = u64::MAX as i64;

type Phone = phone_t;
type Uuid = uuid_t;
type HashSlotIdx = u32;

//
// hash lookup
//

unsafe fn hash_phone_chain_block(
    chain_results: &mut HashSlotResult,
    in_uuid_blocks: &mut [__m256i; 2],
    chain_eq: &[__m256i; CHAIN_BLOCK_COUNT],
    chain_block_idx: usize,
) {
    for (chain_result, in_uuid_block) in chain_results.blocks[chain_block_idx].iter_mut().zip(in_uuid_blocks.iter()) {
        let dummy_write_mask = _mm256_set_epi64x(0, 0, 0, UINT64_MAX);
        *chain_result = _mm256_blendv_epi8(
            _mm256_xor_si256(*chain_result, dummy_write_mask),
            *in_uuid_block,
            chain_eq[chain_block_idx],
        );
    }
}

unsafe fn hash_phone(
    in_phone: &Phone,
    in_uuid: &Uuid,
    hash_key: &HashKey,
    hash_table_order: u32,
    hash_slots: &[HashSlot],
    hash_slot_results: &mut [HashSlotResult],
) {
    // never allow comparing equal to our per-chain-block dummy value of zero
    let chain_block_dummy_mask = _mm256_set_epi64x(0, 0, 0, UINT64_MAX);
    let in_phone_block = _mm256_or_si256(_mm256_set1_epi64x(*in_phone as i64), chain_block_dummy_mask);

    // find the hash slot
    let in_phone_hash_slot_idx = hash_key.hash(in_phone, hash_table_order);

    // search the hash slot chain in each request's hash table
    let hash_slot = hash_slots.get_unchecked(in_phone_hash_slot_idx as usize);

    let chain_eq = [
        _mm256_cmpeq_epi64(in_phone_block, _mm256_loadu_si256(&hash_slot.blocks[0])),
        _mm256_cmpeq_epi64(in_phone_block, _mm256_loadu_si256(&hash_slot.blocks[1])),
        _mm256_cmpeq_epi64(in_phone_block, _mm256_loadu_si256(&hash_slot.blocks[2])),
        _mm256_cmpeq_epi64(in_phone_block, _mm256_loadu_si256(&hash_slot.blocks[3])),
    ];

    // update result bit array, flipping all bits to force a cache line flush
    let mut in_uuid_blocks = [
        _mm256_set1_epi64x(in_uuid.data64[0] as i64),
        _mm256_set1_epi64x(in_uuid.data64[1] as i64),
    ];

    let chain_results = hash_slot_results.get_unchecked_mut(in_phone_hash_slot_idx as usize);
    hash_phone_chain_block(chain_results, &mut in_uuid_blocks, &chain_eq, 0);
    hash_phone_chain_block(chain_results, &mut in_uuid_blocks, &chain_eq, 1);
    hash_phone_chain_block(chain_results, &mut in_uuid_blocks, &chain_eq, 2);
    hash_phone_chain_block(chain_results, &mut in_uuid_blocks, &chain_eq, 3);
}

unsafe fn hash_slot_collect_result(
    chain_results: &mut HashSlotResult,
    chain_eq: &[__m256i; CHAIN_BLOCK_COUNT],
    uuid_data64_idx: usize,
) -> u64 {
    let mut chain_result;
    chain_result = _mm256_setzero_si256();
    chain_result = _mm256_blendv_epi8(chain_result, chain_results.blocks[0][uuid_data64_idx], chain_eq[0]);
    chain_result = _mm256_blendv_epi8(chain_result, chain_results.blocks[1][uuid_data64_idx], chain_eq[1]);
    chain_result = _mm256_blendv_epi8(chain_result, chain_results.blocks[2][uuid_data64_idx], chain_eq[2]);
    chain_result = _mm256_blendv_epi8(chain_result, chain_results.blocks[3][uuid_data64_idx], chain_eq[3]);

    (_mm256_extract_epi64(chain_result, 0)
        | _mm256_extract_epi64(chain_result, 1)
        | _mm256_extract_epi64(chain_result, 2)
        | _mm256_extract_epi64(chain_result, 3)) as u64
}

#[no_mangle]
pub unsafe extern "C" fn cds_contruct_hash(
    in_phones_uuids: InPhonesUuids,
    hash_key: &HashKey,
    hash_table_order: u32,
    hash_slots: &mut [HashSlot],
    hash_slot_results: &mut [HashSlotResult],
) {
    const CACHE_LINE_PHONES: usize = CACHE_LINE_SIZE / size_of::<Phone>();
    const PREFETCH_PHONES_DIST: usize = CACHE_LINE_PHONES * 2;

    let mut in_phone_idx: usize = 0;
    while in_phone_idx + PREFETCH_PHONES_DIST + CACHE_LINE_PHONES < in_phones_uuids.len() {
        in_phones_uuids.prefetch_unchecked(in_phone_idx + PREFETCH_PHONES_DIST);
        for (in_phone, in_uuid) in in_phones_uuids.range_unchecked(in_phone_idx..in_phone_idx + CACHE_LINE_PHONES) {
            hash_phone(&in_phone, &in_uuid, &hash_key, hash_table_order, hash_slots, hash_slot_results);
        }
        in_phone_idx += CACHE_LINE_PHONES;
    }
    for (in_phone, in_uuid) in in_phones_uuids.range_unchecked(in_phone_idx..) {
        hash_phone(&in_phone, &in_uuid, &hash_key, hash_table_order, &hash_slots, hash_slot_results);
    }
}

unsafe fn hash_lookup(
    in_phones_uuids: InPhonesUuids,
    ab_phones: &[Phone],
    ab_phone_results: &mut [u8],
    hash_slots: &mut [HashSlot],
    hash_slot_results: &mut [HashSlotResult],
) -> Result<(), CdsHashLookupError> {
    const CHAIN_LENGTH: HashSlotIdx = CHAIN_PHONE_COUNT;

    let chain_block_dummy_mask = _mm256_set_epi64x(0, 0, 0, UINT64_MAX);
    let chain_block_non_dummy_mask = _mm256_set_epi64x(UINT64_MAX, UINT64_MAX, UINT64_MAX, 0);

    let hash_table_order = hash_slots.len().trailing_zeros();
    if hash_table_order >= 32 || !hash_slots.len().is_power_of_two() {
        return Err(CdsHashLookupError::InvalidParameter);
    }

    // generate random salt
    let hash_key = HashKey::generate().map_err(|()| CdsHashLookupError::RdRand)?;

    // iterate through hash slots
    let mut any_hash_slots_overflowed = false;
    for (hash_slot_idx, hash_slot) in hash_slots.iter_mut().enumerate() {
        // find ab phones to insert into the chain
        // NB: these variables need to be allocated as registers and will leak information if on the stack!
        let mut chain_blocks = [_mm256_setzero_si256(); CHAIN_BLOCK_COUNT];
        let mut chain_block_masks = [
            _mm256_set_epi64x(UINT64_MAX - 0, UINT64_MAX - 1, UINT64_MAX - 2, 0),
            _mm256_set_epi64x(UINT64_MAX - 3, UINT64_MAX - 4, UINT64_MAX - 5, 0),
            _mm256_set_epi64x(UINT64_MAX - 6, UINT64_MAX - 7, UINT64_MAX - 8, 0),
            _mm256_set_epi64x(UINT64_MAX - 9, UINT64_MAX - 10, UINT64_MAX - 11, 0),
        ];
        let mut chain_idx: HashSlotIdx = 0;
        for ab_phone in ab_phones {
            let ab_phone_block = _mm256_set1_epi64x(*ab_phone as i64);
            let ab_phone_hash_slot_idx = hash_key.hash(ab_phone, hash_table_order);

            // branch-less-ly test if hash slot matches
            let hash_slot_matches =
                (((ab_phone_hash_slot_idx as u64 ^ hash_slot_idx as u64) as i64 - 1) as u64 >> (size_of::<HashSlotIdx>() * 8)) & 1;
            //_Static_assert(((int64_t) (((uint64_t) ab_phone_hash_slot_idx) ^ ((uint64_t) hash_slot_idx))) >= 0, "hash_slot_matches overflow");

            // branch-less-ly find out if ab phone is already in chain
            let mut chain_eq = _mm256_cmpeq_epi64(ab_phone_block, chain_blocks[0]);
            chain_eq = _mm256_or_si256(chain_eq, _mm256_cmpeq_epi64(ab_phone_block, chain_blocks[1]));
            chain_eq = _mm256_or_si256(chain_eq, _mm256_cmpeq_epi64(ab_phone_block, chain_blocks[2]));
            chain_eq = _mm256_or_si256(chain_eq, _mm256_cmpeq_epi64(ab_phone_block, chain_blocks[3]));
            let phone_not_in_chain = _mm256_testz_pd(_mm256_castsi256_pd(chain_eq), _mm256_castsi256_pd(chain_eq)) != 0;

            // maybe insert ab phone into the chain
            let should_insert_phone = hash_slot_matches & phone_not_in_chain as u64;
            chain_idx += should_insert_phone as u32;

            chain_blocks[0] = _mm256_castpd_si256(_mm256_blendv_pd(
                _mm256_castsi256_pd(chain_blocks[0]),
                _mm256_castsi256_pd(ab_phone_block),
                _mm256_castsi256_pd(chain_block_masks[0]),
            ));
            chain_blocks[1] = _mm256_castpd_si256(_mm256_blendv_pd(
                _mm256_castsi256_pd(chain_blocks[1]),
                _mm256_castsi256_pd(ab_phone_block),
                _mm256_castsi256_pd(chain_block_masks[1]),
            ));
            chain_blocks[2] = _mm256_castpd_si256(_mm256_blendv_pd(
                _mm256_castsi256_pd(chain_blocks[2]),
                _mm256_castsi256_pd(ab_phone_block),
                _mm256_castsi256_pd(chain_block_masks[2]),
            ));
            chain_blocks[3] = _mm256_castpd_si256(_mm256_blendv_pd(
                _mm256_castsi256_pd(chain_blocks[3]),
                _mm256_castsi256_pd(ab_phone_block),
                _mm256_castsi256_pd(chain_block_masks[3]),
            ));

            chain_block_masks[0] = _mm256_add_epi64(chain_block_masks[0], _mm256_set1_epi64x(should_insert_phone as i64));
            chain_block_masks[1] = _mm256_add_epi64(chain_block_masks[1], _mm256_set1_epi64x(should_insert_phone as i64));
            chain_block_masks[2] = _mm256_add_epi64(chain_block_masks[2], _mm256_set1_epi64x(should_insert_phone as i64));
            chain_block_masks[3] = _mm256_add_epi64(chain_block_masks[3], _mm256_set1_epi64x(should_insert_phone as i64));
        }
        // mask out last processed phone, with non-zero invalid values to force a cache line flush on write
        let dummy_block = _mm256_set1_epi64x(UINT64_MAX);
        chain_blocks[0] = _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(chain_blocks[0]),
            _mm256_castsi256_pd(dummy_block),
            _mm256_castsi256_pd(chain_block_masks[0]),
        ));
        chain_blocks[1] = _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(chain_blocks[1]),
            _mm256_castsi256_pd(dummy_block),
            _mm256_castsi256_pd(chain_block_masks[1]),
        ));
        chain_blocks[2] = _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(chain_blocks[2]),
            _mm256_castsi256_pd(dummy_block),
            _mm256_castsi256_pd(chain_block_masks[2]),
        ));
        chain_blocks[3] = _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(chain_blocks[3]),
            _mm256_castsi256_pd(dummy_block),
            _mm256_castsi256_pd(chain_block_masks[3]),
        ));

        // write out hash slot chain values
        hash_slot.blocks[0] = chain_blocks[0];
        hash_slot.blocks[1] = chain_blocks[1];
        hash_slot.blocks[2] = chain_blocks[2];
        hash_slot.blocks[3] = chain_blocks[3];

        // branch-less-ly trigger a hash table rebuild if too many ab phones hashed to this slot
        any_hash_slots_overflowed |= chain_idx > CHAIN_LENGTH;
    }
    if any_hash_slots_overflowed {
        return Err(CdsHashLookupError::HashTableOverflow);
    }

    cds_contruct_hash(in_phones_uuids, &hash_key, hash_table_order, hash_slots, hash_slot_results);

    // iterate through request phones, collecting results
    for (ab_phone, in_ab_phone_result) in ab_phones.iter().zip(ab_phone_results.chunks_mut(size_of::<Uuid>())) {
        let ab_phone_block = _mm256_set1_epi64x(*ab_phone as i64);
        let mut ab_phone_result = Uuid::default();

        for (hash_slot, chain_results) in hash_slots.iter().zip(hash_slot_results.iter_mut()) {
            let chain_eq = [
                _mm256_cmpeq_epi64(ab_phone_block, _mm256_and_si256(hash_slot.blocks[0], chain_block_non_dummy_mask)),
                _mm256_cmpeq_epi64(ab_phone_block, _mm256_and_si256(hash_slot.blocks[1], chain_block_non_dummy_mask)),
                _mm256_cmpeq_epi64(ab_phone_block, _mm256_and_si256(hash_slot.blocks[2], chain_block_non_dummy_mask)),
                _mm256_cmpeq_epi64(ab_phone_block, _mm256_and_si256(hash_slot.blocks[3], chain_block_non_dummy_mask)),
            ];

            ab_phone_result.data64[0] |= hash_slot_collect_result(chain_results, &chain_eq, 0);
            ab_phone_result.data64[1] |= hash_slot_collect_result(chain_results, &chain_eq, 1);
        }

        (in_ab_phone_result.as_mut_ptr() as *mut u8 as *mut Uuid).write_unaligned(ab_phone_result);
    }

    // write new dummy values to temporary tables (to force erasure of sensitive data)
    for chain_result in hash_slot_results {
        for chain_block_result in &mut chain_result.blocks {
            for chain_block_result_uuid in chain_block_result {
                (chain_block_result_uuid as *mut __m256i).write_volatile(_mm256_xor_si256(
                    _mm256_and_si256(*chain_block_result_uuid, chain_block_dummy_mask),
                    chain_block_dummy_mask,
                ));
            }
        }
    }
    for hash_slot in hash_slots {
        hash_slot.blocks = [_mm256_setzero_si256(); CHAIN_BLOCK_COUNT];
    }

    Ok(())
}

//
// InPhonesUuids
//

mod in_phones_uuids {
    use core::ops::{Bound, RangeBounds};

    use super::*;

    pub struct InPhonesUuids {
        phones: *const phone_t,
        uuids: *const uuid_t,
        len: usize,
    }

    pub struct Iter {
        phones: *const phone_t,
        uuids: *const uuid_t,
        len: usize,
    }

    impl InPhonesUuids {
        pub const CACHE_LINE_UUIDS: usize = CACHE_LINE_SIZE / size_of::<Uuid>();

        pub fn new(phones: *const phone_t, uuids: *const uuid_t, len: usize) -> Self {
            Self { phones, uuids, len }
        }

        pub fn len(&self) -> usize {
            self.len
        }

        /// safety: index <= self.len() - Self::CACHE_LINE_UUIDS
        pub unsafe fn prefetch_unchecked(&self, index: usize) {
            _mm_prefetch(self.phones.add(index) as *const i8, _MM_HINT_NTA);
            _mm_prefetch(self.uuids.add(index) as *const i8, _MM_HINT_NTA);
            _mm_prefetch(self.uuids.add(index + Self::CACHE_LINE_UUIDS) as *const i8, _MM_HINT_NTA);
        }

        pub unsafe fn range_unchecked(&self, range: impl RangeBounds<usize>) -> Iter {
            let start_index = match range.start_bound() {
                Bound::Included(start_index) => *start_index,
                Bound::Excluded(start_index) => start_index + 1,
                Bound::Unbounded => 0,
            };
            let len = match range.end_bound() {
                Bound::Included(end_index) => end_index - start_index + 1,
                Bound::Excluded(end_index) => end_index - start_index,
                Bound::Unbounded => self.len - start_index,
            };
            Iter {
                phones: self.phones.add(start_index),
                uuids: self.uuids.add(start_index),
                len,
            }
        }
    }

    impl Iterator for Iter {
        type Item = (phone_t, uuid_t);

        fn next(&mut self) -> Option<Self::Item> {
            if self.len == 0 {
                return None;
            }
            unsafe {
                let result = (self.phones.read_unaligned(), self.uuids.read_unaligned());
                self.phones = self.phones.add(1);
                self.uuids = self.uuids.add(1);
                self.len -= 1;
                Some(result)
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.len, Some(self.len))
        }
    }
    impl ExactSizeIterator for Iter {}
}

//
// hash_key module
//

mod hash_key {
    use core::arch::x86_64::*;

    pub struct HashKey {
        sk: [__m128i; 11],
    }

    //
    // HashKey impls
    //

    impl HashKey {
        pub unsafe fn generate() -> Result<Self, ()> {
            for _ in 0..10 {
                let mut hash_key_1 = 0;
                let mut hash_key_2 = 0;
                if _rdrand64_step(&mut hash_key_1) == 1 && _rdrand64_step(&mut hash_key_2) == 1 {
                    return Ok(Self::new(&hash_key_1, &hash_key_2));
                }
            }
            Err(())
        }

        pub unsafe fn new(hash_key_1: &u64, hash_key_2: &u64) -> Self {
            let mut hash_key = Self {
                sk: [_mm_setzero_si128(); 11],
            };
            hash_key.set(hash_key_1, hash_key_2);
            hash_key
        }

        pub unsafe fn set(&mut self, hash_key_1: &u64, hash_key_2: &u64) {
            self.sk[0] = _mm_set_epi64x(*hash_key_1 as i64, *hash_key_2 as i64);
            self.sk[1] = expand_step128(self.sk[0], _mm_aeskeygenassist_si128(self.sk[0], 0x01));
            self.sk[2] = expand_step128(self.sk[1], _mm_aeskeygenassist_si128(self.sk[1], 0x02));
            self.sk[3] = expand_step128(self.sk[2], _mm_aeskeygenassist_si128(self.sk[2], 0x04));
            self.sk[4] = expand_step128(self.sk[3], _mm_aeskeygenassist_si128(self.sk[3], 0x08));
            self.sk[5] = expand_step128(self.sk[4], _mm_aeskeygenassist_si128(self.sk[4], 0x10));
            self.sk[6] = expand_step128(self.sk[5], _mm_aeskeygenassist_si128(self.sk[5], 0x20));
            self.sk[7] = expand_step128(self.sk[6], _mm_aeskeygenassist_si128(self.sk[6], 0x40));
            self.sk[8] = expand_step128(self.sk[7], _mm_aeskeygenassist_si128(self.sk[7], 0x80));
            self.sk[9] = expand_step128(self.sk[8], _mm_aeskeygenassist_si128(self.sk[8], 0x1B));
            self.sk[10] = expand_step128(self.sk[9], _mm_aeskeygenassist_si128(self.sk[9], 0x36));
        }

        pub unsafe fn hash(&self, phone: &u64, hash_table_order: u32) -> u32 {
            let mut hash = _mm_cvtsi64_si128(*phone as i64);
            hash = _mm_xor_si128(hash, self.sk[0]);
            hash = _mm_aesenc_si128(hash, self.sk[1]);
            hash = _mm_aesenc_si128(hash, self.sk[2]);
            hash = _mm_aesenc_si128(hash, self.sk[3]);
            hash = _mm_aesenc_si128(hash, self.sk[4]);
            hash = _mm_aesenc_si128(hash, self.sk[5]);
            hash = _mm_aesenc_si128(hash, self.sk[6]);
            hash = _mm_aesenc_si128(hash, self.sk[7]);
            hash = _mm_aesenc_si128(hash, self.sk[8]);
            hash = _mm_aesenc_si128(hash, self.sk[9]);
            hash = _mm_aesenclast_si128(hash, self.sk[10]);

            (_mm_cvtsi128_si32(hash) & ((1u32 << hash_table_order) as i32 - 1)) as u32
        }
    }

    unsafe fn expand_step128(mut k: __m128i, mut k2: __m128i) -> __m128i {
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k2 = _mm_shuffle_epi32(k2, 0xFF);
        _mm_xor_si128(k, k2)
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
