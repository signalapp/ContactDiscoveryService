/*
 * Copyright (C) 2017 Open Whisper Systems
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

 /**
  * @author Jeff Griffin
  */
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <x86intrin.h>

#include "sabd.h"
#include "sgxsd-enclave.h"
#include "sabd_enclave_t.h"

#include "sgx_trts.h"
#include "sgx_lfence.h"

#if UNIT_TESTING
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmockery.h"
#define memset_s(s, smax, c, n) memset(s, c, n);
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define CACHE_LINE_SIZE 64

#define CHAIN_BLOCK_COUNT 3
#define CHAIN_BLOCK_JID_COUNT (32 / sizeof(jid_t))
#define CHAIN_JID_COUNT (CHAIN_BLOCK_COUNT * CHAIN_BLOCK_JID_COUNT)

#ifndef SABD_MAX_HASH_TABLE_ORDER
#define SABD_MAX_HASH_TABLE_ORDER 13
#endif

typedef uint32_t hash_slot_idx_t;
typedef struct sabd_lookup_hash_salt {
  __m128i sk[11];
} sabd_lookup_hash_salt_t;

static inline __m128i
expand_step128(__m128i k, __m128i k2) {
  k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
  k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
  k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
  k2 = _mm_shuffle_epi32(k2, 0xFF);
  return _mm_xor_si128(k, k2);
}
static inline
sabd_lookup_hash_salt_t sabd_lookup_hash_salt(uint64_t hash_salt_64[2]) {
  sabd_lookup_hash_salt_t hash_salt;
  hash_salt.sk[0]  = _mm_set_epi64x(hash_salt_64[0], hash_salt_64[1]);
  hash_salt.sk[1]  = expand_step128(hash_salt.sk[0], _mm_aeskeygenassist_si128(hash_salt.sk[0], 0x01));
  hash_salt.sk[2]  = expand_step128(hash_salt.sk[1], _mm_aeskeygenassist_si128(hash_salt.sk[1], 0x02));
  hash_salt.sk[3]  = expand_step128(hash_salt.sk[2], _mm_aeskeygenassist_si128(hash_salt.sk[2], 0x04));
  hash_salt.sk[4]  = expand_step128(hash_salt.sk[3], _mm_aeskeygenassist_si128(hash_salt.sk[3], 0x08));
  hash_salt.sk[5]  = expand_step128(hash_salt.sk[4], _mm_aeskeygenassist_si128(hash_salt.sk[4], 0x10));
  hash_salt.sk[6]  = expand_step128(hash_salt.sk[5], _mm_aeskeygenassist_si128(hash_salt.sk[5], 0x20));
  hash_salt.sk[7]  = expand_step128(hash_salt.sk[6], _mm_aeskeygenassist_si128(hash_salt.sk[6], 0x40));
  hash_salt.sk[8]  = expand_step128(hash_salt.sk[7], _mm_aeskeygenassist_si128(hash_salt.sk[7], 0x80));
  hash_salt.sk[9]  = expand_step128(hash_salt.sk[8], _mm_aeskeygenassist_si128(hash_salt.sk[8], 0x1B));
  hash_salt.sk[10] = expand_step128(hash_salt.sk[9], _mm_aeskeygenassist_si128(hash_salt.sk[9], 0x36));
  return hash_salt;
}

static inline
hash_slot_idx_t sabd_lookup_hash_slot(jid_t jid, sabd_lookup_hash_salt_t hash_salt, uint32_t hash_table_order) {
  __m128i hash = _mm_cvtsi64_si128(jid);
  hash =        _mm_xor_si128(hash, hash_salt.sk[0]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[1]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[2]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[3]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[4]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[5]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[6]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[7]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[8]);
  hash =     _mm_aesenc_si128(hash, hash_salt.sk[9]);
  hash = _mm_aesenclast_si128(hash, hash_salt.sk[10]);

  return _mm_cvtsi128_si32(hash) & ((1 << hash_table_order) - 1);
}

sgx_status_t sabd_lookup_hash(const jid_t *in_jids, size_t in_jid_count,
                              const jid_t *ab_jids, hash_slot_idx_t ab_jid_count,
                              volatile uint8_t *in_ab_jids_result) {
  const hash_slot_idx_t chain_length = CHAIN_JID_COUNT;

  // calculate hash table size = ab_jid_count rounded up to the nearest power of 2
  uint32_t hash_table_order = likely(ab_jid_count > 1)? _bit_scan_reverse(ab_jid_count - 1) + 1 : 0;

  // validate hash table size
  if (unlikely(ab_jid_count == 0)) {
    return SGX_SUCCESS;
  }
  if (unlikely(hash_table_order > SABD_MAX_HASH_TABLE_ORDER)) {
    return SGX_ERROR_INVALID_PARAMETER;
  }
  _Static_assert((((hash_slot_idx_t) 1) << SABD_MAX_HASH_TABLE_ORDER) > 0, "hash_table_slot_count overflow");
  hash_slot_idx_t hash_table_slot_count = ((hash_slot_idx_t) 1) << hash_table_order;
  _Static_assert((((hash_slot_idx_t) 1) << SABD_MAX_HASH_TABLE_ORDER) < (UINT32_MAX / chain_length), "hash_table_jid_count overflow");
  hash_slot_idx_t hash_table_jid_count = hash_table_slot_count * chain_length;

  // allocate hash table and auxilary tables
  _Static_assert(hash_table_slot_count < (SIZE_MAX / sizeof(jid_t)) / chain_length, "hashed_ab_jids size overflow");
  size_t hashed_ab_jids_size = hash_table_jid_count * sizeof(jid_t);
  jid_t *hashed_ab_jids = memalign(CACHE_LINE_SIZE, hashed_ab_jids_size);
  if (unlikely(hashed_ab_jids == NULL)) {
    return SGX_ERROR_OUT_OF_MEMORY;
  }

  size_t in_hashed_ab_jids_result_bits_size = hash_table_slot_count * sizeof(uint16_t);
  volatile uint16_t *in_hashed_ab_jids_result_bits = memalign(CACHE_LINE_SIZE, in_hashed_ab_jids_result_bits_size);
  _Static_assert(sizeof(*in_hashed_ab_jids_result_bits) * 8 > CHAIN_JID_COUNT, "hash chain fits in result bit array");
  if (unlikely(in_hashed_ab_jids_result_bits == NULL)) {
    free(hashed_ab_jids);
    return SGX_ERROR_OUT_OF_MEMORY;
  }
  memset_s(in_hashed_ab_jids_result_bits, in_hashed_ab_jids_result_bits_size, 0, in_hashed_ab_jids_result_bits_size);

  // write dummy values to result byte array first, so both true and false force a cache line flush
  memset_s(in_ab_jids_result, ab_jid_count, 0xFF, ab_jid_count);

  // fill hash table with zeroes to force a cache line flush on write below
  memset_s(hashed_ab_jids, hashed_ab_jids_size, 0, hashed_ab_jids_size);

  // repeat hash table construction until no hash slots overflow
  sabd_lookup_hash_salt_t hash_salt;
  bool hash_table_constructed = false;
  for (uint32_t hash_table_tries = 0; !hash_table_constructed && likely(hash_table_tries < 128); hash_table_tries++) {
    // generate random salt
    uint64_t hash_salt_64[2];
    bool hash_salt_rand_res = false;
    for (uint32_t hash_salt_rand_tries = 0; likely(hash_salt_rand_tries < 10); hash_salt_rand_tries++) {
      if (likely(_rdrand64_step(&hash_salt_64[0])) && likely(_rdrand64_step(&hash_salt_64[1]))) {
        hash_salt_rand_res = true;
        break;
      }
    }
    if (unlikely(!hash_salt_rand_res)) {
      break;
    }
    hash_salt = sabd_lookup_hash_salt(hash_salt_64);

    // iterate through hash slots
    bool any_hash_slots_overflowed = false;
    for (hash_slot_idx_t hash_slot_idx = 0; likely(hash_slot_idx < hash_table_slot_count); hash_slot_idx++) {
      // find ab jids to insert into the chain
      // NB: these variables need to be allocated as registers and will leak information if on the stack!
      register __m256i chain_blocks[CHAIN_BLOCK_COUNT] = {0};
      register __m256i chain_block_masks[] = {
        _mm256_set_epi64x(UINT64_MAX - 0, UINT64_MAX - 1, UINT64_MAX - 2, UINT64_MAX - 3),
        _mm256_set_epi64x(UINT64_MAX - 4, UINT64_MAX - 5, UINT64_MAX - 6, UINT64_MAX - 7),
        _mm256_set_epi64x(UINT64_MAX - 8, UINT64_MAX - 9, UINT64_MAX - 10, UINT64_MAX - 11),
      };
      hash_slot_idx_t chain_idx = 0;
      for (hash_slot_idx_t ab_jid_idx = 0; likely(ab_jid_idx < ab_jid_count); ab_jid_idx++) {
        jid_t ab_jid = ab_jids[ab_jid_idx];
        __m256i ab_jid_block = _mm256_set1_epi64x(ab_jid);
        hash_slot_idx_t ab_jid_hash_slot_idx = sabd_lookup_hash_slot(ab_jid, hash_salt, hash_table_order);

        // branch-less-ly test if hash slot matches
        uint64_t hash_slot_matches =
          (((uint64_t) (((int64_t) (((uint64_t) ab_jid_hash_slot_idx) ^ ((uint64_t) hash_slot_idx))) - 1))
           >> (sizeof(hash_slot_idx) * 8)) & 1;
        // NB: re-work above expression if this assert fails
        _Static_assert(((int64_t) (((uint64_t) ab_jid_hash_slot_idx) ^ ((uint64_t) hash_slot_idx))) >= 0, "hash_slot_matches overflow");

        // branch-less-ly find out if ab jid is already in chain
        __m256i chain_eq =                   _mm256_cmpeq_epi64(ab_jid_block, chain_blocks[0]);
        chain_eq = _mm256_or_si256(chain_eq, _mm256_cmpeq_epi64(ab_jid_block, chain_blocks[1]));
        chain_eq = _mm256_or_si256(chain_eq, _mm256_cmpeq_epi64(ab_jid_block, chain_blocks[2]));
        bool jid_not_in_chain = _mm256_testz_pd((__m256d) chain_eq, (__m256d) chain_eq);

        // maybe insert ab jid into the chain
        uint64_t should_insert_jid = hash_slot_matches & jid_not_in_chain;
        chain_idx += should_insert_jid;

        chain_blocks[0] = (__m256i) _mm256_blendv_pd((__m256d) chain_blocks[0], (__m256d) ab_jid_block, (__m256d) chain_block_masks[0]);
        chain_blocks[1] = (__m256i) _mm256_blendv_pd((__m256d) chain_blocks[1], (__m256d) ab_jid_block, (__m256d) chain_block_masks[1]);
        chain_blocks[2] = (__m256i) _mm256_blendv_pd((__m256d) chain_blocks[2], (__m256d) ab_jid_block, (__m256d) chain_block_masks[2]);

        chain_block_masks[0] = _mm256_add_epi64(chain_block_masks[0], _mm256_set1_epi64x(should_insert_jid));
        chain_block_masks[1] = _mm256_add_epi64(chain_block_masks[1], _mm256_set1_epi64x(should_insert_jid));
        chain_block_masks[2] = _mm256_add_epi64(chain_block_masks[2], _mm256_set1_epi64x(should_insert_jid));
      }
      // mask out last processed jid, with non-zero invalid values to force a cache line flush on write
      __m256i dummy_block = _mm256_set1_epi8(UINT8_MAX);
      chain_blocks[0] = (__m256i) _mm256_blendv_pd((__m256d) chain_blocks[0], (__m256d) dummy_block, (__m256d) chain_block_masks[0]);
      chain_blocks[1] = (__m256i) _mm256_blendv_pd((__m256d) chain_blocks[1], (__m256d) dummy_block, (__m256d) chain_block_masks[1]);
      chain_blocks[2] = (__m256i) _mm256_blendv_pd((__m256d) chain_blocks[2], (__m256d) dummy_block, (__m256d) chain_block_masks[2]);

      // write out hash slot chain values
      __m256i *p_chain_blocks = (__m256i *) &hashed_ab_jids[hash_slot_idx * chain_length];
      p_chain_blocks[0] = chain_blocks[0];
      p_chain_blocks[1] = chain_blocks[1];
      p_chain_blocks[2] = chain_blocks[2];

      // branch-less-ly trigger a hash table rebuild if too many ab jids hashed to this slot
      any_hash_slots_overflowed |= chain_idx > chain_length;
    }
    hash_table_constructed = !any_hash_slots_overflowed;
    if (unlikely(!hash_table_constructed)) {
      memset_s(hashed_ab_jids, hashed_ab_jids_size, 0, hashed_ab_jids_size);
    }
    #ifdef UNIT_TESTING
    if (hash_table_constructed) {
      check_expected(hash_table_tries);
    }
    #endif
  }
  if (unlikely(!hash_table_constructed)) {
    free((void *) in_hashed_ab_jids_result_bits);
    free(hashed_ab_jids);
    return SGX_ERROR_UNEXPECTED;
  }

  for (size_t in_jid_idx = 0; likely(in_jid_idx < in_jid_count); in_jid_idx++) {
    jid_t in_jid = in_jids[in_jid_idx];
    __m256i in_jid_block = _mm256_set1_epi64x(in_jid);

    // find the hash slot
    hash_slot_idx_t in_jid_hash_slot_idx = sabd_lookup_hash_slot(in_jid, hash_salt, hash_table_order);

    // search the hash slot chain in each request's hash table
    __m256i *chain_blocks = (__m256i *) &hashed_ab_jids[in_jid_hash_slot_idx * chain_length];
    uint16_t chain_eq_mask =
      (_mm256_movemask_pd((__m256d) _mm256_cmpeq_epi64(in_jid_block, chain_blocks[0])) << 0) |
      (_mm256_movemask_pd((__m256d) _mm256_cmpeq_epi64(in_jid_block, chain_blocks[1])) << 4) |
      (_mm256_movemask_pd((__m256d) _mm256_cmpeq_epi64(in_jid_block, chain_blocks[2])) << 8);

    // update result bit array, flipping some bits to force a cache line flush
    volatile uint16_t *chain_result_bits = &in_hashed_ab_jids_result_bits[in_jid_hash_slot_idx];
    *chain_result_bits = (*chain_result_bits ^ 0xF000) | chain_eq_mask;
  }

  // iterate through request jids, collecting results
  for (hash_slot_idx_t ab_jid_idx = 0; likely(ab_jid_idx < ab_jid_count); ab_jid_idx++) {
    jid_t ab_jid = ab_jids[ab_jid_idx];
    __m256i ab_jid_block = _mm256_set1_epi64x(ab_jid);
    uint16_t ab_jid_result = 0;

    for (hash_slot_idx_t hash_slot_idx = 0; likely(hash_slot_idx < hash_table_slot_count); hash_slot_idx++) {
      __m256i *chain_blocks = (__m256i *) &hashed_ab_jids[hash_slot_idx * chain_length];
      uint16_t chain_eq_mask =
        (_mm256_movemask_pd((__m256d) _mm256_cmpeq_epi64(ab_jid_block, chain_blocks[0])) << 0) |
        (_mm256_movemask_pd((__m256d) _mm256_cmpeq_epi64(ab_jid_block, chain_blocks[1])) << 4) |
        (_mm256_movemask_pd((__m256d) _mm256_cmpeq_epi64(ab_jid_block, chain_blocks[2])) << 8);
      uint16_t chain_result = in_hashed_ab_jids_result_bits[hash_slot_idx] & 0xFFF;
      ab_jid_result |= chain_eq_mask & chain_result;
    }

    in_ab_jids_result[ab_jid_idx] = !!ab_jid_result;
  }

  // write new dummy values to temporary tables (to force erasure of sensitive data)
  for (hash_slot_idx_t hash_slot_idx = 0; likely(hash_slot_idx < hash_table_slot_count); hash_slot_idx++) {
    in_hashed_ab_jids_result_bits[hash_slot_idx] = 0x8000;
    volatile __m256i *chain_blocks = (__m256i *) &hashed_ab_jids[hash_slot_idx * chain_length];
    chain_blocks[0] = _mm256_setzero_si256();
    chain_blocks[1] = _mm256_setzero_si256();
    chain_blocks[2] = _mm256_setzero_si256();
  }

  free((void *) in_hashed_ab_jids_result_bits);
  free(hashed_ab_jids);
  return SGX_SUCCESS;
}

//
// sgxsd callbacks
//

typedef struct sabd_msg {
  sgxsd_msg_from_t from;
  hash_slot_idx_t ab_jid_count;
  struct sabd_msg *prev;
} sabd_msg_t;

typedef struct sgxsd_server_state {
  sabd_msg_t *msgs;
  hash_slot_idx_t ab_jid_count;
  hash_slot_idx_t max_ab_jids;
  _Alignas(CACHE_LINE_SIZE) jid_t ab_jids[];
} sgxsd_server_state_t, sabd_state_t;

sgx_status_t sgxsd_enclave_server_init(const sabd_start_args_t *p_args, sabd_state_t **pp_state) {
  if (p_args == NULL) {
    return SGX_ERROR_INVALID_PARAMETER;
  }

  _Static_assert(p_args->max_ab_jids < (SIZE_MAX - sizeof(sabd_state_t)) / sizeof(jid_t), "state_size overflow");
  size_t state_size = sizeof(sabd_state_t) + sizeof(jid_t) * p_args->max_ab_jids;
  sabd_state_t *p_state = memalign(CACHE_LINE_SIZE, state_size);
  if (p_state == NULL) {
    return SGX_ERROR_OUT_OF_MEMORY;
  }
  memset_s(p_state, state_size, 0, state_size);
  *p_state = (sabd_state_t) {
    .msgs = NULL,
    .ab_jid_count = 0,
    .max_ab_jids = p_args->max_ab_jids,
  };
  *pp_state = p_state;
  return SGX_SUCCESS;
}
sgx_status_t sgxsd_enclave_server_handle_call(const sabd_call_args_t *p_args,
                                              sgxsd_msg_buf_t msg, sgxsd_msg_from_t from,
                                              sabd_state_t **pp_state) {
  sabd_state_t *p_state = *pp_state;
  if (p_state == NULL) {
    return SGX_ERROR_INVALID_STATE;
  }
  if (p_args == NULL) {
    return SGX_ERROR_INVALID_PARAMETER;
  }
  if (p_args->ab_jid_count == 0 ||
      p_args->ab_jid_count > p_state->max_ab_jids - p_state->ab_jid_count ||
      msg.size % 8 != 0 ||
      msg.size / 8 != p_args->ab_jid_count) {
    return SGX_ERROR_INVALID_PARAMETER;
  }
  sgx_lfence();

  sabd_msg_t *p_sabd_msg = malloc(sizeof(sabd_msg_t));
  if (p_sabd_msg == NULL) {
    return SGX_ERROR_OUT_OF_MEMORY;
  }
  *p_sabd_msg = (sabd_msg_t) {
    .from = from,
    .prev = p_state->msgs,
    .ab_jid_count = p_args->ab_jid_count,
  };
  p_state->msgs = p_sabd_msg;
  memcpy(&p_state->ab_jids[p_state->ab_jid_count], msg.data, msg.size);
  p_state->ab_jid_count += p_sabd_msg->ab_jid_count;

  memset_s(&from, sizeof(from), 0, sizeof(from));

  return SGX_SUCCESS;
}
sgx_status_t sgxsd_enclave_server_terminate(const sabd_stop_args_t *p_args, sabd_state_t *p_state) {
  if (p_state == NULL) {
    return SGX_ERROR_INVALID_STATE;
  }

  sgx_status_t validate_args_res = SGX_ERROR_INVALID_PARAMETER;
  size_t validated_in_jid_count = 0;
  if (p_args == NULL) {
    validate_args_res = SGX_ERROR_INVALID_PARAMETER;
  } else {
    // make sure in_jids is outside of the enclave
    size_t in_jids_size = p_args->in_jid_count * sizeof(p_args->in_jids[0]);
    if (p_args->in_jid_count > SIZE_MAX / sizeof(p_args->in_jids[0]) ||
        sgx_is_outside_enclave(p_args->in_jids, in_jids_size) != 1) {
      validate_args_res = SGX_ERROR_INVALID_PARAMETER;
    } else {
      validated_in_jid_count = in_jids_size / sizeof(p_args->in_jids[0]);
      validate_args_res = SGX_SUCCESS;
    }
  }

  sgx_status_t lookup_res;
  sgx_status_t replies_res = SGX_SUCCESS;
  if (p_state->ab_jid_count != 0) {
    uint8_t *in_ab_jids_result = malloc(p_state->ab_jid_count);
    if (validate_args_res != SGX_SUCCESS) {
      // failed to validate lookup args
      lookup_res = validate_args_res;
    } else if (in_ab_jids_result != NULL) {
      // prevent speculative execution in case in_jids lies inside enclave
      sgx_lfence();

      lookup_res = sabd_lookup_hash(p_args->in_jids, validated_in_jid_count,
                                    p_state->ab_jids, p_state->ab_jid_count,
                                    in_ab_jids_result);
    } else {
      lookup_res = SGX_ERROR_OUT_OF_MEMORY;
    }

    hash_slot_idx_t ab_jid_idx = p_state->ab_jid_count;
    for (sabd_msg_t *p_msg = p_state->msgs; p_msg != NULL;) {
      if (lookup_res == SGX_SUCCESS) {
        ab_jid_idx -= p_msg->ab_jid_count;
        sgxsd_msg_buf_t reply_buf = {
          .data = &in_ab_jids_result[ab_jid_idx],
          .size = p_msg->ab_jid_count,
        };
        // sgxsd_enclave_server_reply overwrites reply_buf.data
        sgx_status_t reply_res = sgxsd_enclave_server_reply(reply_buf, p_msg->from);
        if (replies_res == SGX_SUCCESS) {
          replies_res = reply_res;
        }
      }

      sabd_msg_t *p_prev_msg = p_msg->prev;
      memset_s(p_msg, sizeof(*p_msg), 0, sizeof(*p_msg));
      free(p_msg);
      p_msg = p_prev_msg;
    }

    free(in_ab_jids_result);
  } else {
    lookup_res = validate_args_res;
  }

  size_t state_size = sizeof(sabd_state_t) + sizeof(jid_t) * p_state->max_ab_jids;
  memset_s(p_state, state_size, 0, state_size);
  free(p_state);
  if (lookup_res == SGX_SUCCESS) {
    if (replies_res == SGX_ERROR_INVALID_PARAMETER) {
      return SGX_ERROR_UNEXPECTED;
    }
    return replies_res;
  } else {
    return lookup_res;
  }
}
