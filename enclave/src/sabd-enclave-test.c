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
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <time.h>

#include "sgx_trts.h"

#include "sabd.h"
#include "sgxsd-enclave.h"

#include "cmockery.h"

bool benchmark;
#define BENCHMARK_IN_JID_COUNT_STEPS 3
#define BENCHMARK_AB_JID_COUNT_STEPS 3
#define BENCHMARK_TEST_RUN_COUNT     2

uint32_t test_run_count = 4;

long int test_drand48_seed;
struct drand48_data test_drand48_data;

sgxsd_server_state_t *p_server_state;
sabd_start_args_t *p_empty_start_args;
sgxsd_msg_buf_t valid_msg_buf;
sgxsd_msg_buf_t valid_reply;
sgxsd_msg_from_t dummy_msg_from;
sabd_call_args_t *p_valid_call_args;
sabd_stop_args_t *p_empty_stop_args;
sabd_stop_args_t *p_valid_stop_args;

jid_t *test_in_jids;
const size_t test_in_jid_count = 1000*1000;
uint32_t benchmark_in_jid_count_steps = 0;
size_t test_in_jid_count_step_factor = 10;

jid_t *test_ab_jids;
const uint32_t test_ab_jid_count = 2048;
uint32_t benchmark_ab_jid_count_steps = 0;
uint32_t test_ab_jid_count_step_factor = 2;

uint8_t *test_expected_in_ab_jids_result;

uint32_t test_hash_table_overflow_ab_jid_count   = 16;
// check overflow rate < 1 / 1e6 = 0.0001%
uint32_t test_hash_table_overflow_max_count      = 0;
uint32_t test_hash_table_overflow_run_count      = 1e6;
// in benchmark mode, check overflow rate < 1 / 1e6 = 0.0001%
uint32_t benchmark_hash_table_overflow_run_count = 1e7;

void setup_sabd_lookup_test(size_t in_jid_count, jid_t *ab_jids, uint32_t ab_jid_count, uint8_t *expected_in_ab_jids_result) {
  for (uint32_t ab_jid_idx = 0; ab_jid_idx < ab_jid_count; ab_jid_idx++) {
    long int rand;
    mrand48_r(&test_drand48_data, &rand);
    uint32_t rand_idx = rand % (in_jid_count * 2);
    if (rand_idx < in_jid_count) {
      ab_jids[ab_jid_idx] = test_in_jids[rand_idx];
      expected_in_ab_jids_result[ab_jid_idx] = 1;
    } else {
      ab_jids[ab_jid_idx] = 1;
      expected_in_ab_jids_result[ab_jid_idx] = 0;
    }
  }
}

void setup_tests(void **state) {
  print_message("using seed: 0x%08lx\n", test_drand48_seed);
  srand48_r(test_drand48_seed, &test_drand48_data);

  size_t max_in_jid_count = test_in_jid_count;
  if (benchmark) {
    benchmark_in_jid_count_steps = BENCHMARK_IN_JID_COUNT_STEPS;
  }
  for (uint32_t in_jid_count_step = 1; in_jid_count_step < benchmark_in_jid_count_steps; in_jid_count_step++) {
    max_in_jid_count *= test_in_jid_count_step_factor;
  }
  test_in_jids = memalign(64, max_in_jid_count * sizeof(jid_t));
  for (size_t test_in_jid_idx = 0; test_in_jid_idx < max_in_jid_count; test_in_jid_idx++) {
    long int rand;
    mrand48_r(&test_drand48_data, &rand);
    jid_t jid = rand;
    mrand48_r(&test_drand48_data, &rand);
    jid |= ((long unsigned int) rand) << 32;
    test_in_jids[test_in_jid_idx] = jid;
  }

  if (benchmark) {
    benchmark_ab_jid_count_steps = BENCHMARK_AB_JID_COUNT_STEPS;
  }
  test_ab_jids = memalign(64, test_ab_jid_count * sizeof(jid_t));
  test_expected_in_ab_jids_result = test_malloc(test_ab_jid_count);
  setup_sabd_lookup_test(test_in_jid_count, test_ab_jids, test_ab_jid_count, test_expected_in_ab_jids_result);

  // server_start test arguments
  p_empty_start_args = test_malloc(sizeof(sabd_start_args_t));
  *p_empty_start_args = (sabd_start_args_t) { .max_ab_jids = 0 };

  // server_call test arguments
  valid_msg_buf = (sgxsd_msg_buf_t) { .data = (uint8_t *) test_in_jids, .size = sizeof(jid_t) };
  valid_reply = (sgxsd_msg_buf_t) { .data = test_expected_in_ab_jids_result, .size = 1 };
  dummy_msg_from = (sgxsd_msg_from_t) { .tag = { .p_tag = NULL }, .server_key = {{0}}};
  p_valid_call_args = test_malloc(sizeof(sabd_call_args_t));
  *p_valid_call_args = (sabd_call_args_t) { .ab_jid_count = 1 };

  // server_terminate test arguments
  p_empty_stop_args = test_malloc(sizeof(sabd_stop_args_t));
  *p_empty_stop_args = (sabd_stop_args_t) { .in_jids = NULL, .in_jid_count = 0 };
  p_valid_stop_args = test_malloc(sizeof(sabd_stop_args_t));
  *p_valid_stop_args = (sabd_stop_args_t) { .in_jids = test_in_jids, .in_jid_count = 1 };
}

void teardown_tests(void **state) {
  test_free(test_in_jids);
  test_free(test_ab_jids);
  test_free(test_expected_in_ab_jids_result);
  test_free(p_empty_start_args);
  test_free(p_valid_call_args);
  test_free(p_empty_stop_args);
  test_free(p_valid_stop_args);
}

void setup_sabd_server_test(void **state) {
  p_server_state = NULL;
}
void teardown_sabd_server_test(void **state) {
  assert_int_equal(p_server_state, NULL);
}

void test_sabd_server_init(sgx_status_t res, sabd_start_args_t args) {
  assert_int_equal(p_server_state, NULL);
  // allocate on heap to get -fsanitize=address instrumentation
  sabd_start_args_t *p_args_copy = test_malloc(sizeof(args));
  *p_args_copy = args;
  p_server_state = NULL;
  assert_int_equal(res, sgxsd_enclave_server_init(p_args_copy, &p_server_state));
  if (res == SGX_SUCCESS) {
    assert_int_not_equal(p_server_state, NULL);
  } else {
    assert_int_equal(p_server_state, NULL);
  }
  test_free(p_args_copy);
}

void test_sabd_server_call(sgx_status_t res, sgxsd_msg_buf_t *expected_reply,
                           sabd_call_args_t args, sgxsd_msg_buf_t msg, sgxsd_msg_from_t from) {

  // allocate on heap to get -fsanitize=address instrumentation
  sabd_call_args_t *p_args_copy = test_malloc(sizeof(args));
  *p_args_copy = args;

  sgxsd_server_state_t *p_new_server_state = p_server_state;
  assert_int_equal(res, sgxsd_enclave_server_handle_call(p_args_copy, msg, from, &p_new_server_state));

  test_free(p_args_copy);

  if (expected_reply != NULL) {
    expect_value(sgxsd_enclave_server_reply, reply_buf.size, expected_reply->size);
    expect_any(sgxsd_enclave_server_reply, reply_buf.data);
    //expect_memory(sgxsd_enclave_server_reply, reply_buf.data, expected_reply->data, expected_reply->size);
    will_return(sgxsd_enclave_server_reply, (sgx_status_t) { SGX_SUCCESS });
  }

  // state pointer currently never changes
  assert_int_equal(p_new_server_state, p_server_state);
}

void test_sabd_server_term(sgx_status_t res, sabd_stop_args_t args) {
  assert_in_range(args.in_jid_count, 0, SIZE_MAX / sizeof(args.in_jids[0]));
  will_return(sgx_is_outside_enclave, (int) { 1 });

  // allocate on heap to get -fsanitize=address instrumentation
  sabd_stop_args_t *p_args_copy = test_malloc(sizeof(args));
  *p_args_copy = args;
  assert_int_equal(res, sgxsd_enclave_server_terminate(p_args_copy, p_server_state));
  test_free(p_args_copy);
  p_server_state = NULL;
}

void test_sabd_server_null_state(void **state) {
  // test NULL state checks
  test_sabd_server_call(SGX_ERROR_INVALID_STATE, NULL,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_terminate(p_empty_stop_args, NULL));
  p_server_state = NULL;
}

void test_sabd_server_in_jids_outside_enclave(void **state) {
  test_sabd_server_init(SGX_SUCCESS, *p_empty_start_args);
  will_return(sgx_is_outside_enclave, (int) { 0 });
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_terminate(p_valid_stop_args, p_server_state));
  p_server_state = NULL;
}
void test_sabd_server_in_jids_overflow(void **state) {
  test_sabd_server_init(SGX_SUCCESS, *p_empty_start_args);
  sabd_stop_args_t *p_in_jid_overflow_stop_args = malloc(sizeof(sabd_stop_args_t));
  *p_in_jid_overflow_stop_args = (sabd_stop_args_t) {
    .in_jids = p_valid_stop_args->in_jids,
    .in_jid_count = p_valid_stop_args->in_jid_count + SIZE_MAX / sizeof(p_valid_stop_args->in_jids[0]),
  };
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_terminate
                   (p_in_jid_overflow_stop_args, p_server_state));
  test_free(p_in_jid_overflow_stop_args);
  p_server_state = NULL;
}

void test_sabd_server_init_invalid_args(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_init(NULL, &p_server_state));
  assert_int_equal(p_server_state, NULL);
}

void test_sabd_server_call_invalid_args(void **state) {
  test_sabd_server_init(SGX_SUCCESS, *p_empty_start_args);
  sgxsd_server_state_t *p_valid_server_state = p_server_state;
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_handle_call
                   (NULL, valid_msg_buf, dummy_msg_from, &p_server_state));
  assert_int_equal(p_server_state, p_valid_server_state);
  test_sabd_server_term(SGX_SUCCESS, *p_empty_stop_args);
}
void test_sabd_server_term_invalid_args(void **state) {
  test_sabd_server_init(SGX_SUCCESS, *p_empty_start_args);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_terminate(NULL, p_server_state));
  p_server_state = NULL;
}

void test_sabd_server_zero_max_batch(void **state) {
  test_sabd_server_init(SGX_SUCCESS, (sabd_start_args_t) { .max_ab_jids = 0 });
  test_sabd_server_term(SGX_SUCCESS, *p_empty_stop_args);
}

void test_sabd_server_empty_batch(void **state) {
  test_sabd_server_init(SGX_SUCCESS, (sabd_start_args_t) { .max_ab_jids = 1 });
  test_sabd_server_term(SGX_SUCCESS, *p_valid_stop_args);
}

void test_sabd_server_empty_msg(void **state) {
  test_sabd_server_init(SGX_SUCCESS, *p_empty_start_args);
  test_sabd_server_call(SGX_ERROR_INVALID_PARAMETER, NULL,
                        (sabd_call_args_t) { .ab_jid_count = 0 },
                        (sgxsd_msg_buf_t)  { .data = NULL, .size = 0 },
                        dummy_msg_from);
  test_sabd_server_term(SGX_SUCCESS, *p_empty_stop_args);
}

void test_sabd_server_invalid_msg_size(void **state) {
  test_sabd_server_init(SGX_SUCCESS, *p_empty_start_args);
  test_sabd_server_call(SGX_ERROR_INVALID_PARAMETER, NULL,
                        (sabd_call_args_t) { .ab_jid_count = 1 },
                        (sgxsd_msg_buf_t)  { .data = valid_msg_buf.data, .size = valid_msg_buf.size - 1 },
                        dummy_msg_from);
  test_sabd_server_term(SGX_SUCCESS, *p_empty_stop_args);
}

void test_sabd_server_msg_size_mismatch(void **state) {
  test_sabd_server_init(SGX_SUCCESS, *p_empty_start_args);
  test_sabd_server_call(SGX_ERROR_INVALID_PARAMETER, NULL,
                        (sabd_call_args_t) { .ab_jid_count = 2 },
                        valid_msg_buf,
                        dummy_msg_from);
  test_sabd_server_term(SGX_SUCCESS, *p_empty_stop_args);
}

void test_sabd_server_valid_msg(void **state) {
  test_sabd_server_init(SGX_SUCCESS, (sabd_start_args_t) { .max_ab_jids = 1 });
  test_sabd_server_call(SGX_SUCCESS, &valid_reply,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  expect_any(sabd_lookup_hash, hash_table_tries);
  test_sabd_server_term(SGX_SUCCESS, *p_valid_stop_args);
}

void test_sabd_server_batch_overflow_0(void **state) {
  test_sabd_server_init(SGX_SUCCESS, (sabd_start_args_t) { .max_ab_jids = 0 });
  test_sabd_server_call(SGX_ERROR_INVALID_PARAMETER, NULL,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  test_sabd_server_term(SGX_SUCCESS, *p_empty_stop_args);
}

void test_sabd_server_batch_overflow_1(void **state) {
  test_sabd_server_init(SGX_SUCCESS, (sabd_start_args_t) { .max_ab_jids = 1 });
  test_sabd_server_call(SGX_SUCCESS, &valid_reply,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  test_sabd_server_call(SGX_ERROR_INVALID_PARAMETER, NULL,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  expect_any(sabd_lookup_hash, hash_table_tries);
  test_sabd_server_term(SGX_SUCCESS, *p_empty_stop_args);
}

void test_sabd_server_reply_fail(void **state) {
  test_sabd_server_init(SGX_SUCCESS, (sabd_start_args_t) { .max_ab_jids = 3 });
  test_sabd_server_call(SGX_SUCCESS, &valid_reply,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  test_sabd_server_call(SGX_SUCCESS, NULL,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  expect_any(sgxsd_enclave_server_reply, reply_buf.size);
  expect_any(sgxsd_enclave_server_reply, reply_buf.data);
  will_return(sgxsd_enclave_server_reply, (sgx_status_t) { SGX_ERROR_UNEXPECTED });
  test_sabd_server_call(SGX_SUCCESS, &valid_reply,
                        *p_valid_call_args, valid_msg_buf, dummy_msg_from);
  expect_any(sabd_lookup_hash, hash_table_tries);
  test_sabd_server_term(SGX_ERROR_UNEXPECTED, *p_empty_stop_args);
}

sgx_status_t sabd_lookup_hash(const jid_t *in_jids, size_t in_jid_count,
                              const jid_t *ab_jids, uint32_t ab_jid_count,
                              volatile uint8_t *in_ab_jids_result);
static
void test_sabd_lookup_batch_too_large(void **state) {
  uint32_t ab_jid_count = ((uint32_t) { 1 } << 14) + 1;
  jid_t *ab_jids = test_calloc(ab_jid_count, sizeof(jid_t));
  uint8_t *in_ab_jids_result = test_malloc(ab_jid_count);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sabd_lookup_hash
                   (test_in_jids, test_in_jid_count, ab_jids, ab_jid_count, in_ab_jids_result));
  test_free(in_ab_jids_result);
  test_free(ab_jids);
}
void test_sabd_lookup(size_t in_jid_count, jid_t *ab_jids, uint32_t ab_jid_count, const uint8_t *expected_in_ab_jids_result) {
  uint8_t *in_ab_jids_result = test_calloc(ab_jid_count, 1);
  if (ab_jid_count != 0) {
    expect_any(sabd_lookup_hash, hash_table_tries);
  }
  assert_int_equal(SGX_SUCCESS, sabd_lookup_hash
                   (test_in_jids, in_jid_count, ab_jids, ab_jid_count, in_ab_jids_result));
  for (uint32_t ab_jid_idx = 0; ab_jid_idx < ab_jid_count; ab_jid_idx++) {
    in_ab_jids_result[ab_jid_idx] = !!(in_ab_jids_result[ab_jid_idx]);
  }
  assert_memory_equal(in_ab_jids_result, expected_in_ab_jids_result, ab_jid_count);
  test_free(in_ab_jids_result);
}
static
void test_sabd_lookup_many_duplicates(void **state) {
  uint32_t ab_jid_count = test_ab_jid_count;
  size_t ab_jids_size = ab_jid_count * sizeof(jid_t);
  jid_t *ab_jids = test_malloc(ab_jids_size);
  memcpy(ab_jids, test_ab_jids, ab_jids_size);
  uint8_t *expected_in_ab_jids_result = test_malloc(ab_jid_count);
  memcpy(expected_in_ab_jids_result, test_expected_in_ab_jids_result, ab_jid_count);
  for (uint32_t ab_jid_idx = 0; ab_jid_idx < ab_jid_count; ab_jid_idx += 2) {
    ab_jids[ab_jid_idx] = ab_jids[0];
    expected_in_ab_jids_result[ab_jid_idx] = expected_in_ab_jids_result[0];
  }
  test_sabd_lookup(test_in_jid_count, ab_jids, ab_jid_count, expected_in_ab_jids_result);
  test_free(expected_in_ab_jids_result);
  test_free(ab_jids);
}
static
void test_sabd_lookup_small(bool use_in_jids) {
  uint32_t max_ab_jid_count = 32;
  jid_t *ab_jids = test_malloc(max_ab_jid_count * sizeof(jid_t));
  uint8_t *expected_in_ab_jids_result = test_malloc(max_ab_jid_count);
  for (uint32_t test_ab_jid_idx = 0, ab_jid_idx = 0;
       test_ab_jid_idx < test_ab_jid_count && ab_jid_idx < max_ab_jid_count;
       test_ab_jid_idx++) {
    if (test_expected_in_ab_jids_result[test_ab_jid_idx] == use_in_jids) {
      expected_in_ab_jids_result[ab_jid_idx] = use_in_jids;
      ab_jids[ab_jid_idx++] = test_ab_jids[test_ab_jid_idx];
    }
  }
  for (uint32_t ab_jid_count = 0; ab_jid_count <= max_ab_jid_count; ab_jid_count++) {
    test_sabd_lookup(test_in_jid_count, ab_jids, ab_jid_count, expected_in_ab_jids_result);
  }
  test_free(expected_in_ab_jids_result);
  test_free(ab_jids);
}
static
void test_sabd_lookup_small_all_in_jids(void **state) {
  test_sabd_lookup_small(true);
}
static
void test_sabd_lookup_small_no_in_jids(void **state) {
  test_sabd_lookup_small(false);
}
static
void test_sabd_lookup_small_random(void **state) {
  for (uint32_t ab_jid_count = 0; ab_jid_count <= 25; ab_jid_count++) {
    test_sabd_lookup(test_in_jid_count, test_ab_jids, ab_jid_count, test_expected_in_ab_jids_result);
  }
}
static
void test_sabd_lookup_large(void **state) {
  test_sabd_lookup(test_in_jid_count, test_ab_jids, test_ab_jid_count, test_expected_in_ab_jids_result);
}

static
int test_sabd_lookup_hash_table_overflow_check(LargestIntegralType value, LargestIntegralType check_value_data) {
  uint32_t *p_overflow_count = (uint32_t *) check_value_data;
  *p_overflow_count += value;
  return true;
}
static
void test_sabd_lookup_hash_table_overflow(void **state) {
  uint32_t ab_jid_count = test_hash_table_overflow_ab_jid_count;
  uint8_t *in_ab_jids_result = test_malloc(ab_jid_count);
  uint32_t overflow_count = 0;
  uint32_t run_count = benchmark? benchmark_hash_table_overflow_run_count : test_hash_table_overflow_run_count;
  // divide (rounded up) by how many times we're going to run this test in total
  run_count = (run_count + test_run_count - 1) / test_run_count;
  _expect_check("sabd_lookup_hash", "hash_table_tries", __FILE__, __LINE__,
                test_sabd_lookup_hash_table_overflow_check, cast_to_largest_integral_type(&overflow_count),
                NULL, run_count);
  for (uint32_t run_idx = 0; run_idx < run_count; run_idx++) {
    assert_int_equal(SGX_SUCCESS, sabd_lookup_hash(test_in_jids, 0, test_ab_jids, ab_jid_count, in_ab_jids_result));
  }
  print_message("finished %zu %zu-jid ab lookups with %zu overflows (< %g%%)\n",
                run_count, ab_jid_count, overflow_count, (overflow_count + 1) * 100.0 / run_count);
  assert_in_range(overflow_count, 0, test_hash_table_overflow_max_count);
  test_free(in_ab_jids_result);
}

static
void test_sabd_lookup_benchmark(void **state) {
  size_t in_jid_count = test_in_jid_count;
  for (uint32_t in_jid_count_step = 0; in_jid_count_step < benchmark_in_jid_count_steps; in_jid_count_step++) {
    uint32_t ab_jid_count = test_ab_jid_count;
    for (uint32_t ab_jid_count_step = 0; ab_jid_count_step < benchmark_ab_jid_count_steps; ab_jid_count_step++) {
      jid_t *ab_jids = memalign(64, ab_jid_count * sizeof(jid_t));
      uint8_t *expected_in_ab_jids_result = test_malloc(ab_jid_count);
      setup_sabd_lookup_test(in_jid_count, ab_jids, ab_jid_count, expected_in_ab_jids_result);
    
      struct timespec lookup_start;
      clock_gettime(CLOCK_THREAD_CPUTIME_ID, &lookup_start);

      test_sabd_lookup(in_jid_count, ab_jids, ab_jid_count, expected_in_ab_jids_result);

      struct timespec lookup_end;
      clock_gettime(CLOCK_THREAD_CPUTIME_ID, &lookup_end);
      double lookup_elapsed =
        (lookup_end.tv_sec + lookup_end.tv_nsec / 1e9) - (lookup_start.tv_sec + lookup_start.tv_nsec / 1e9);
      print_message("finished %5zu jid ab lookup on %10zu jids in %0.3gs (%'#0.4gs / ab jid)\n",
                    ab_jid_count, in_jid_count, lookup_elapsed, lookup_elapsed / ab_jid_count);

      test_free(ab_jids);
      test_free(expected_in_ab_jids_result);

      ab_jid_count *= test_ab_jid_count_step_factor;
    }
    in_jid_count *= test_in_jid_count_step_factor;
  }
}

int sgx_is_outside_enclave(const void *addr, size_t size) {
  return (int) mock();
}

sgx_status_t sgxsd_enclave_server_reply(sgxsd_msg_buf_t reply_buf, sgxsd_msg_from_t from) {
  check_expected(reply_buf.size);
  check_expected(reply_buf.data);
  return (sgx_status_t) mock();
}

#define unit_test_sabd_server(test) unit_test_setup_teardown(test, setup_sabd_server_test, teardown_sabd_server_test)

int main(int argc, char *argv[]) {
  for (int arg_idx = 1; arg_idx < argc; arg_idx++) {
    if (strcmp(argv[arg_idx], "--benchmark") == 0) {
      benchmark = true;
    } else {
      print_error("Usage: %s [--benchmark]\n", argv[0]);
      return 1;
    }
  }

  UnitTest tests[] = {
    unit_test_setup(tests, setup_tests),
    unit_test_sabd_server(test_sabd_server_null_state),
    unit_test_sabd_server(test_sabd_server_in_jids_outside_enclave),
    unit_test_sabd_server(test_sabd_server_in_jids_overflow),
    unit_test_sabd_server(test_sabd_server_init_invalid_args),
    unit_test_sabd_server(test_sabd_server_call_invalid_args),
    unit_test_sabd_server(test_sabd_server_term_invalid_args),
    unit_test_sabd_server(test_sabd_server_zero_max_batch),
    unit_test_sabd_server(test_sabd_server_empty_batch),
    unit_test_sabd_server(test_sabd_server_empty_msg),
    unit_test_sabd_server(test_sabd_server_invalid_msg_size),
    unit_test_sabd_server(test_sabd_server_msg_size_mismatch),
    unit_test_sabd_server(test_sabd_server_valid_msg),
    unit_test_sabd_server(test_sabd_server_batch_overflow_0),
    unit_test_sabd_server(test_sabd_server_batch_overflow_1),
    unit_test_sabd_server(test_sabd_server_reply_fail),
    unit_test(test_sabd_lookup_batch_too_large),
    unit_test(test_sabd_lookup_many_duplicates),
    unit_test(test_sabd_lookup_small_no_in_jids),
    unit_test(test_sabd_lookup_small_all_in_jids),
    unit_test(test_sabd_lookup_small_random),
    unit_test(test_sabd_lookup_large),
    unit_test(test_sabd_lookup_hash_table_overflow),
    unit_test(test_sabd_lookup_benchmark),
    unit_test_teardown(tests, teardown_tests),
  };
  if (benchmark) {
    test_run_count = BENCHMARK_TEST_RUN_COUNT;
  }
  for (int test_run = 0; test_run < test_run_count; test_run++) {
    int res = run_tests(tests) != 0;
    if (res != 0) {
      return res;
    }
    mrand48_r(&test_drand48_data, &test_drand48_seed);
    test_drand48_seed &= UINT32_MAX;
  }
  return 0;
}
