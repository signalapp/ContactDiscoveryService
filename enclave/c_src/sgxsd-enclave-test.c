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
#include <stdlib.h>
#include <stdbool.h>

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_spinlock.h"
#include "sgx_quote.h"

#include "bearssl.h"
#include "sgxsd-enclave.h"
#include "cds.h"
#include "cmockery.h"

sgx_status_t sgxsd_enclave_node_init(const sgxsd_node_init_args_t* p_args);
sgx_status_t sgxsd_enclave_get_next_report(sgx_target_info_t qe_target_info, sgx_report_t *p_report);
sgx_status_t sgxsd_enclave_set_current_quote();
sgx_status_t sgxsd_enclave_negotiate_request(const sgxsd_request_negotiation_request_t *p_request, sgxsd_request_negotiation_response_t *p_response);
sgx_status_t sgxsd_enclave_server_start(const sgxsd_server_init_args_t* p_args, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_ratelimit_fingerprint(uint8_t fingerprint_key[32],
                                                 const sgxsd_server_handle_call_args_t *call_args,
                                                 const sgxsd_msg_header_t *msg_header,
                                                 uint8_t *msg_data, size_t msg_data_size,
                                                 sgxsd_msg_tag_t msg_tag,
                                                 sgxsd_server_state_handle_t state_handle,
                                                 uint8_t *fingerprint, size_t fingerprint_size);
        sgx_status_t sgxsd_enclave_server_call(const sgxsd_server_handle_call_args_t* p_args, const sgxsd_msg_header_t* msg_header, const uint8_t* msg_data, size_t msg_size, sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_server_stop(const sgxsd_server_terminate_args_t* p_args, sgxsd_server_state_handle_t state_handle);

extern void *g_sgxsd_enclave_pending_requests;

sgx_status_t sgxsd_ocall_reply(sgx_status_t* retval, const sgxsd_msg_header_t* reply_header, const uint8_t* reply_data, size_t reply_data_size, sgxsd_msg_tag_t msg_tag);

void test_read_rand(void *dst, size_t size);
void expect_sgx_read_rand(sgx_status_t res, unsigned char **p_rand, size_t expected_length_in_bytes);
void expect_sgxsd_enclave_server_init(sgx_status_t res, void *expected_args, size_t expected_args_size);
void expect_sgxsd_enclave_server_handle_call(sgx_status_t res, sgxsd_server_handle_call_args_t *expected_args,
                                             sgxsd_msg_buf_t expected_msg, sgxsd_msg_from_t expected_from);
void expect_sgxsd_enclave_server_terminate(sgx_status_t res, void *expected_args, size_t expected_args_size);
void expect_sgxsd_aes_gcm_encrypt(sgx_status_t res,
                                  const sgxsd_aes_gcm_key_t *expected_p_key,
                                  void *expected_p_src, uint32_t expected_src_len, bool capture_src,
                                  void **pp_expected_dst,
                                  const sgxsd_aes_gcm_iv_t *expected_p_iv,
                                  const void *expected_p_aad, uint32_t expected_aad_len,
                                  sgxsd_aes_gcm_mac_t **pp_expected_out_mac);
void expect_sgxsd_aes_gcm_decrypt(sgx_status_t res,
                                  const sgxsd_aes_gcm_key_t *expected_p_key,
                                  const void *expected_p_src, uint32_t expected_src_len,
                                  void **pp_expected_dst,
                                  const sgxsd_aes_gcm_iv_t *expected_p_iv,
                                  const void *expected_p_aad, uint32_t expected_aad_len,
                                  const sgxsd_aes_gcm_mac_t *expected_p_in_mac);
void expect_sgxsd_ocall_reply(sgx_status_t ocall_res, sgx_status_t res,
                              const void *p_expected_dst, size_t expected_reply_data_size,
                              const void *expected_iv, size_t expected_iv_len,
                              const sgxsd_aes_gcm_mac_t *p_expected_out_mac,
                              uint64_t expected_tag);
void expect_sgxsd_ocall_noreply(sgx_status_t ocall_res, sgx_status_t res,
                                uint64_t expected_tag);
void expect_sgxsd_enclave_create_ratelimit_fingerprint(sgx_status_t res,
                                                       uint8_t expected_fingerprint_key[32],
                                                       const sgxsd_server_handle_call_args_t *expected_args,
                                                       sgxsd_msg_buf_t expected_msg,
                                                       sgxsd_msg_from_t expected_from,
                                                       size_t expected_fingerprint_size);

//
// globals
//

long int test_drand48_seed;
struct drand48_data test_drand48_data;

sgxsd_node_init_args_t *test_node_init_args;

sgxsd_request_negotiation_request_t *p_test_request_negotiation_request;
sgx_target_info_t test_qe_target_info;
sgx_report_t *p_test_report;

sgxsd_server_state_handle_t valid_server_handle = 0;
sgxsd_server_state_handle_t invalid_server_handle = UINT64_MAX;
void *test_args;
size_t test_args_size;
sgxsd_msg_buf_t test_msg_buf;

sgxsd_msg_header_t test_msg_header;

sgxsd_msg_buf_t null_msg_buf  = { .data = NULL, .size = 0 };
sgxsd_msg_buf_t empty_msg_buf = { .data = NULL, .size = 0 };
sgxsd_msg_from_t valid_msg_from;

sgxsd_aes_gcm_iv_t *test_zero_iv;

sgxsd_server_handle_call_args_t *old_call_args;
uint8_t *call_data;
uint8_t *fingerprint_out;

static void setup_tests(void **state) {
  print_message("using seed: 0x%08lx\n", test_drand48_seed);
  srand48_r(test_drand48_seed, &test_drand48_data);

  test_node_init_args = test_malloc(sizeof(*test_node_init_args));
  *test_node_init_args = (sgxsd_node_init_args_t) {
    .pending_requests_table_order = 0,
  };

  empty_msg_buf.data = malloc(0);

  long int test_args_size_rand;
  lrand48_r(&test_drand48_data, &test_args_size_rand);
  test_args_size = 1 + (test_args_size_rand & 0xFFFF);
  print_message("using test args of size %zu\n", test_args_size);
  test_args = test_malloc(test_args_size);
  test_read_rand(test_args, test_args_size);

  long int test_msg_buf_size_rand;
  lrand48_r(&test_drand48_data, &test_msg_buf_size_rand);
  test_msg_buf.size = 1 + (test_msg_buf_size_rand & 0xFFFF);
  print_message("using test msg of size %zu\n", test_msg_buf.size);
  test_msg_buf.data = test_malloc(test_msg_buf.size);
  test_read_rand(test_msg_buf.data, test_msg_buf.size);

  p_test_request_negotiation_request = test_malloc(sizeof(*p_test_request_negotiation_request));
  test_read_rand(p_test_request_negotiation_request, sizeof(*p_test_request_negotiation_request));
  test_read_rand(&test_qe_target_info, sizeof(test_qe_target_info));
  p_test_report = test_malloc(sizeof(*p_test_report));
  test_read_rand(p_test_report, sizeof(*p_test_report));

  test_read_rand(&test_msg_header.iv, sizeof(test_msg_header.iv));
  test_read_rand(&test_msg_header.mac, sizeof(test_msg_header.mac));

  test_read_rand(&valid_msg_from, sizeof(valid_msg_from));
  valid_msg_from.valid = true;

  test_zero_iv = test_malloc(sizeof(*test_zero_iv));
  memset(test_zero_iv, 0, sizeof(*test_zero_iv));

  size_t call_data_size = 100;
  call_data = test_malloc(call_data_size);
  cds_encrypted_msg_t query = {{{2}}, {{3}}, call_data_size, call_data};
  old_call_args = test_malloc(sizeof(sgxsd_server_handle_call_args_t));
  old_call_args->query_phone_count = 1;
  old_call_args->ratelimit_state_size = 0;
  memset(old_call_args->ratelimit_state_uuid.data64, 5, sizeof(old_call_args->ratelimit_state_uuid.data64));
  old_call_args->ratelimit_state_data = NULL;
  old_call_args->query = query;
  memset(old_call_args->query_commitment, 4, sizeof(old_call_args->query_commitment));

  fingerprint_out = test_malloc(old_call_args->query_phone_count);
}

static void teardown_tests(void **state) {
  test_free(test_zero_iv);
  test_free(test_node_init_args);
  test_free(test_args);
  test_free(test_msg_buf.data);
  test_free(empty_msg_buf.data);
  test_free(p_test_request_negotiation_request);
  test_free(p_test_report);
  test_free(call_data);
  test_free(old_call_args);
  test_free(fingerprint_out);
}

static void teardown_node_tests(void **state) {
  // allocated by node_init
  test_free(g_sgxsd_enclave_pending_requests);
}

static void test_noop(void **state) {
}

//
// node init tests
//

static void test_sgxsd_node_init_rand_error(void **state) {
  will_return(sgx_is_outside_enclave, 1);
  will_return(sgx_is_outside_enclave, 1);
  expect_sgx_read_rand(SGX_ERROR_UNEXPECTED, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  assert_int_equal(SGX_ERROR_UNEXPECTED, sgxsd_enclave_node_init(test_node_init_args));

  will_return(sgx_is_outside_enclave, 1);
  will_return(sgx_is_outside_enclave, 1);
  expect_sgx_read_rand(SGX_SUCCESS, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  expect_sgx_read_rand(SGX_ERROR_UNEXPECTED, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  assert_int_equal(SGX_ERROR_UNEXPECTED, sgxsd_enclave_node_init(test_node_init_args));

  will_return(sgx_is_outside_enclave, 1);
  will_return(sgx_is_outside_enclave, 1);
  expect_sgx_read_rand(SGX_SUCCESS, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  expect_sgx_read_rand(SGX_SUCCESS, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  expect_sgx_read_rand(SGX_ERROR_UNEXPECTED, NULL, sizeof(sgxsd_aes_gcm_key_t));
  assert_int_equal(SGX_ERROR_UNEXPECTED, sgxsd_enclave_node_init(test_node_init_args));
}
static void test_sgxsd_node_init_null_args(void **state) {
  will_return(sgx_is_outside_enclave, 1);
  will_return(sgx_is_outside_enclave, 1);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_node_init(NULL));
}
static void test_sgxsd_node_init_pending_requests_table_order_too_large(void **state) {
  will_return(sgx_is_outside_enclave, 1);
  will_return(sgx_is_outside_enclave, 1);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_node_init
                   (&(sgxsd_node_init_args_t) { .pending_requests_table_order = 64 }));

  will_return(sgx_is_outside_enclave, 1);
  will_return(sgx_is_outside_enclave, 1);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_node_init
                   (&(sgxsd_node_init_args_t) { .pending_requests_table_order = UINT8_MAX }));
}
static void test_sgxsd_node_init(void **state) {
  will_return(sgx_is_outside_enclave, 1);
  will_return(sgx_is_outside_enclave, 1);
  expect_sgx_read_rand(SGX_SUCCESS, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  expect_sgx_read_rand(SGX_SUCCESS, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  expect_sgx_read_rand(SGX_SUCCESS, NULL, sizeof(sgxsd_aes_gcm_key_t));
  assert_int_equal(SGX_SUCCESS, sgxsd_enclave_node_init(test_node_init_args));
}
static void test_sgxsd_node_init_already_initialized(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_node_init(test_node_init_args));
}

//
// get_next_report tests
//

static void test_sgxsd_get_next_report_node_uninitialized(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_get_next_report
                   (test_qe_target_info, p_test_report));
}
static void test_sgxsd_get_next_report_null_report(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_get_next_report
                   (test_qe_target_info, NULL));
}

//
// set_current_quote tests
//

static void test_sgxsd_set_current_quote_node_uninitialized(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_set_current_quote());
}

//
// negotiate_request tests
//

static void test_sgxsd_negotiate_request_node_uninitialized(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_negotiate_request
                   (p_test_request_negotiation_request, &(sgxsd_request_negotiation_response_t) {0}));
}
static void test_sgxsd_negotiate_request_null_request(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_negotiate_request
                   (NULL, &(sgxsd_request_negotiation_response_t) {0}));
}
static void test_sgxsd_negotiate_request_null_response(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_negotiate_request
                   (p_test_request_negotiation_request, NULL));
}
static void test_sgxsd_negotiate_request_generate_keypair_rand_error(void **state) {
  expect_sgx_read_rand(SGX_ERROR_UNEXPECTED, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  assert_int_equal(SGX_ERROR_UNEXPECTED, sgxsd_enclave_negotiate_request
                   (p_test_request_negotiation_request, &(sgxsd_request_negotiation_response_t) {0}));
}

static void test_sgxsd_negotiate_request(uint8_t *expected_pending_request_id, sgxsd_pending_request_id_t *p_pending_request_id) {
  expect_sgx_read_rand(SGX_SUCCESS, NULL, sizeof((sgxsd_curve25519_private_key_t*){0}->x));
  uint8_t *expected_p_iv_data;
  expect_sgx_read_rand(SGX_SUCCESS, &expected_p_iv_data, sizeof(sgxsd_aes_gcm_iv_t));
  sgxsd_aes_gcm_iv_t *expected_p_iv = (sgxsd_aes_gcm_iv_t *) expected_p_iv_data;

  expect_sgxsd_aes_gcm_encrypt(SGX_SUCCESS, NULL,
                               expected_pending_request_id, sizeof(p_pending_request_id->data), true, NULL,
                               expected_p_iv, NULL, 0, NULL);

  void *p_expected_dst;
  sgxsd_aes_gcm_mac_t *p_expected_out_mac;
  expect_sgxsd_aes_gcm_encrypt(SGX_SUCCESS, NULL,
                               p_pending_request_id, sizeof(*p_pending_request_id), true, &p_expected_dst,
                               test_zero_iv, NULL, 0, &p_expected_out_mac);
  assert_int_equal(SGX_SUCCESS, sgxsd_enclave_negotiate_request
                   (p_test_request_negotiation_request, &(sgxsd_request_negotiation_response_t) {0}));
}

//
// server start tests
//

static void test_sgxsd_server_start_node_uninitialized(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_start(NULL, valid_server_handle));
}
static void test_sgxsd_server_start_invalid_handle(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_start(NULL, invalid_server_handle));
}
static void test_sgxsd_server_start_already_started(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_start(NULL, valid_server_handle));
}
static void test_sgxsd_server_start_init_error(void **state) {
  expect_sgxsd_enclave_server_init(SGX_ERROR_UNEXPECTED, test_args, test_args_size);
  assert_int_equal(SGX_ERROR_UNEXPECTED, sgxsd_enclave_server_start(test_args, valid_server_handle));
}
static void test_sgxsd_server_start_valid(void **state) {
  expect_sgxsd_enclave_server_init(SGX_SUCCESS, test_args, test_args_size);
  assert_int_equal(SGX_SUCCESS, sgxsd_enclave_server_start(test_args, valid_server_handle));
}

//
// server call tests
//

static void test_sgxsd_server_call_node_uninitialized(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, test_msg_buf.data, test_msg_buf.size, valid_msg_from.tag,
                    valid_server_handle));
}
static void test_sgxsd_server_call_invalid_request_id(void **state) {
  memset(&test_msg_header.pending_request_id, 0, sizeof(test_msg_header.pending_request_id));
  expect_sgxsd_aes_gcm_decrypt(SGX_ERROR_MAC_MISMATCH, NULL,
                               &test_msg_header.pending_request_id.data, sizeof(test_msg_header.pending_request_id.data),
                               NULL,
                               &test_msg_header.pending_request_id.iv,
                               NULL, 0,
                               &test_msg_header.pending_request_id.mac);
  assert_int_equal(SGX_ERROR_MAC_MISMATCH, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, test_msg_buf.data, test_msg_buf.size, valid_msg_from.tag,
                    valid_server_handle));
}
static void test_sgxsd_server_call_invalid_handle(void **state) {
  test_sgxsd_negotiate_request(NULL, &test_msg_header.pending_request_id);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, test_msg_buf.data, test_msg_buf.size, valid_msg_from.tag,
                    invalid_server_handle));
}
static void test_sgxsd_server_call_not_started(void **state) {
  test_sgxsd_negotiate_request(NULL, &test_msg_header.pending_request_id);
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, test_msg_buf.data, test_msg_buf.size, valid_msg_from.tag,
                    valid_server_handle));
}
static void test_sgxsd_server_call(sgx_status_t res, sgx_status_t decrypt_msg_res,
                                   sgx_status_t handle_call_res, sgxsd_msg_buf_t msg) {
  uint8_t expected_pending_request_id[sizeof(test_msg_header.pending_request_id.data)];
  test_sgxsd_negotiate_request(&expected_pending_request_id[0], &test_msg_header.pending_request_id);

  void *p_expected_pending_request_id_data;
  expect_sgxsd_aes_gcm_decrypt(SGX_SUCCESS, NULL,
                               &test_msg_header.pending_request_id.data, sizeof(test_msg_header.pending_request_id.data),
                               &p_expected_pending_request_id_data,
                               &test_msg_header.pending_request_id.iv,
                               NULL, 0,
                               &test_msg_header.pending_request_id.mac);
  memcpy(p_expected_pending_request_id_data, &expected_pending_request_id, sizeof(expected_pending_request_id));

  void *p_expected_decrypted_msg_buf_data;
  expect_sgxsd_aes_gcm_decrypt(decrypt_msg_res, NULL,
                               msg.data, msg.size,
                               &p_expected_decrypted_msg_buf_data,
                               &test_msg_header.iv,
                               &test_msg_header.pending_request_id, sizeof(test_msg_header.pending_request_id),
                               &test_msg_header.mac);
  sgxsd_msg_buf_t expected_decrypted_msg_buf = { .data = p_expected_decrypted_msg_buf_data, .size = msg.size };
  if (decrypt_msg_res == SGX_SUCCESS) {
    expect_sgxsd_enclave_server_handle_call(handle_call_res, old_call_args,
                                            expected_decrypted_msg_buf, valid_msg_from);
  }
  assert_int_equal(res, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, msg.data, msg.size, valid_msg_from.tag, valid_server_handle));
}
static void test_sgxsd_server_call_decrypt_msg_error(void **state) {
  test_sgxsd_server_call(SGX_ERROR_UNEXPECTED, SGX_ERROR_UNEXPECTED, SGX_SUCCESS, test_msg_buf);
}
static void test_sgxsd_server_call_handler_error(void **state) {
  test_sgxsd_server_call(SGX_ERROR_UNEXPECTED, SGX_SUCCESS, SGX_ERROR_UNEXPECTED, test_msg_buf);
}
static void test_sgxsd_server_call_empty(void **state) {
  test_sgxsd_negotiate_request(NULL, &test_msg_header.pending_request_id);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, NULL, 0, valid_msg_from.tag,
                    valid_server_handle));
}
static void test_sgxsd_server_call_invalid_null_data(void **state) {
  // SGX Edger8r-generated interfaces pass through NULL data pointers along with non-zero data size
  test_sgxsd_negotiate_request(NULL, &test_msg_header.pending_request_id);
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, NULL, 1, valid_msg_from.tag,
                    valid_server_handle));
}
static void test_sgxsd_server_call_valid(void **state) {
  test_sgxsd_server_call(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, test_msg_buf);
}
static void test_sgxsd_server_call_replay(void **state) {
  test_sgxsd_server_call(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, test_msg_buf);
  expect_sgxsd_aes_gcm_decrypt(SGX_SUCCESS, NULL,
                               &test_msg_header.pending_request_id.data, sizeof(test_msg_header.pending_request_id.data),
                               NULL,
                               &test_msg_header.pending_request_id.iv,
                               NULL, 0,
                               &test_msg_header.pending_request_id.mac);
  assert_int_equal(SGXSD_ERROR_PENDING_REQUEST_NOT_FOUND, sgxsd_enclave_server_call
                   (old_call_args, &test_msg_header, test_msg_buf.data, test_msg_buf.size, valid_msg_from.tag, valid_server_handle));
}


//
// ratelimit fingerprint tests
//

static uint8_t valid_fingerprint_key[32] = {1,2,3,4,5,6,7};

static void test_sgxsd_ratelimit_fingerprint_golden_path(void **state) {
    sgxsd_msg_buf_t msg = test_msg_buf;
    uint8_t expected_pending_request_id[sizeof(test_msg_header.pending_request_id.data)];
    test_sgxsd_negotiate_request(&expected_pending_request_id[0], &test_msg_header.pending_request_id);

    void *p_expected_pending_request_id_data;
    expect_sgxsd_aes_gcm_decrypt(SGX_SUCCESS, NULL,
                                 &test_msg_header.pending_request_id.data, sizeof(test_msg_header.pending_request_id.data),
                                 &p_expected_pending_request_id_data,
                                 &test_msg_header.pending_request_id.iv,
                                 NULL, 0,
                                 &test_msg_header.pending_request_id.mac);
    memcpy(p_expected_pending_request_id_data, &expected_pending_request_id, sizeof(expected_pending_request_id));

    void *p_expected_decrypted_msg_buf_data;
    expect_sgxsd_aes_gcm_decrypt(SGX_SUCCESS, NULL,
                                 msg.data, msg.size,
                                 &p_expected_decrypted_msg_buf_data,
                                 &test_msg_header.iv,
                                 &test_msg_header.pending_request_id, sizeof(test_msg_header.pending_request_id),
                                 &test_msg_header.mac);
    sgxsd_msg_buf_t expected_decrypted_msg_buf = { .data = p_expected_decrypted_msg_buf_data, .size = msg.size };
    expect_sgxsd_enclave_create_ratelimit_fingerprint(SGX_SUCCESS, valid_fingerprint_key, old_call_args,
                                                      expected_decrypted_msg_buf, valid_msg_from,
                                                      old_call_args->query_phone_count);

    assert_int_equal(SGX_SUCCESS, sgxsd_enclave_ratelimit_fingerprint
            (valid_fingerprint_key, old_call_args, &test_msg_header, msg.data, msg.size, valid_msg_from.tag, valid_server_handle, fingerprint_out, old_call_args->query_phone_count));
}

static void test_sgxsd_ratelimit_fingerprint_call_still_valid(void **state) {
    sgxsd_msg_buf_t msg = test_msg_buf;
    uint8_t expected_pending_request_id[sizeof(test_msg_header.pending_request_id.data)];
    test_sgxsd_negotiate_request(&expected_pending_request_id[0], &test_msg_header.pending_request_id);

    void *p_expected_pending_request_id_data;
    expect_sgxsd_aes_gcm_decrypt(SGX_SUCCESS, NULL,
                                 &test_msg_header.pending_request_id.data, sizeof(test_msg_header.pending_request_id.data),
                                 &p_expected_pending_request_id_data,
                                 &test_msg_header.pending_request_id.iv,
                                 NULL, 0,
                                 &test_msg_header.pending_request_id.mac);
    memcpy(p_expected_pending_request_id_data, &expected_pending_request_id, sizeof(expected_pending_request_id));

    void *p_expected_decrypted_msg_buf_data;
    expect_sgxsd_aes_gcm_decrypt(SGX_SUCCESS, NULL,
                                 msg.data, msg.size,
                                 &p_expected_decrypted_msg_buf_data,
                                 &test_msg_header.iv,
                                 &test_msg_header.pending_request_id, sizeof(test_msg_header.pending_request_id),
                                 &test_msg_header.mac);
    sgxsd_msg_buf_t expected_decrypted_msg_buf = { .data = p_expected_decrypted_msg_buf_data, .size = msg.size };
    expect_sgxsd_enclave_create_ratelimit_fingerprint(SGX_SUCCESS, valid_fingerprint_key, old_call_args,
                                                      expected_decrypted_msg_buf, valid_msg_from,
                                                      old_call_args->query_phone_count);

    assert_int_equal(SGX_SUCCESS, sgxsd_enclave_ratelimit_fingerprint
            (valid_fingerprint_key, old_call_args, &test_msg_header, msg.data, msg.size, valid_msg_from.tag, valid_server_handle, fingerprint_out, old_call_args->query_phone_count));
    test_sgxsd_server_call_valid(state);
}

//
// server stop tests
//

static void test_sgxsd_server_stop_node_uninitialized(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_stop(NULL, valid_server_handle));
}
static void test_sgxsd_server_stop_invalid_handle(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_start(NULL, invalid_server_handle));
}
static void test_sgxsd_server_stop_already_stopped(void **state) {
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_stop(NULL, valid_server_handle));
}
static void test_sgxsd_server_stop_terminate_error(void **state) {
  expect_sgxsd_enclave_server_terminate(SGX_ERROR_UNEXPECTED, test_args, test_args_size);
  assert_int_equal(SGX_ERROR_UNEXPECTED, sgxsd_enclave_server_stop(test_args, valid_server_handle));
}
static void test_sgxsd_server_stop_valid(void **state) {
  expect_sgxsd_enclave_server_terminate(SGX_SUCCESS, test_args, test_args_size);
  assert_int_equal(SGX_SUCCESS, sgxsd_enclave_server_stop(test_args, valid_server_handle));
}

//
// reply tests
//

static void test_sgxsd_server_reply(sgx_status_t res,
                                    sgx_status_t encrypt_res, sgx_status_t reply_ocall_res, sgx_status_t reply_res,
                                    sgxsd_msg_buf_t reply_buf, sgxsd_msg_from_t *p_msg_from) {
  sgxsd_msg_from_t msg_from = valid_msg_from;
  if (p_msg_from == NULL) {
    p_msg_from = &msg_from;
  }

  uint8_t *expected_iv_data;
  expect_sgx_read_rand(SGX_SUCCESS, &expected_iv_data, sizeof(((sgxsd_aes_gcm_iv_t *) 0)->data));
  sgxsd_aes_gcm_iv_t *expected_iv = (sgxsd_aes_gcm_iv_t *) expected_iv_data;
  expected_iv->data[0] |= 1;
  void *p_expected_dst;
  sgxsd_aes_gcm_mac_t *p_expected_out_mac;
  expect_sgxsd_aes_gcm_encrypt(encrypt_res, NULL,
                               reply_buf.data, reply_buf.size, false, &p_expected_dst,
                               expected_iv, NULL, 0, &p_expected_out_mac);
  if (encrypt_res == SGX_SUCCESS) {
    expect_sgxsd_ocall_reply(reply_ocall_res, reply_res, p_expected_dst, reply_buf.size,
                             expected_iv, sizeof(expected_iv->data),
                             p_expected_out_mac,
                             p_msg_from->tag.tag);
  }

  assert_int_equal(res, sgxsd_enclave_server_reply(reply_buf, p_msg_from));
}

static void test_sgxsd_server_noreply(sgx_status_t res, sgx_status_t reply_ocall_res, sgx_status_t reply_res,
                                      sgxsd_msg_from_t *p_msg_from) {
  sgxsd_msg_from_t msg_from = valid_msg_from;
  if (p_msg_from == NULL) {
    p_msg_from = &msg_from;
  }

  expect_sgxsd_ocall_noreply(reply_ocall_res, reply_res, p_msg_from->tag.tag);
  assert_int_equal(res, sgxsd_enclave_server_noreply(p_msg_from));
}

static void test_sgxsd_server_reply_invalid_buf(void **state) {
  sgxsd_msg_from_t msg_from = valid_msg_from;
  assert_int_equal(SGX_ERROR_INVALID_PARAMETER, sgxsd_enclave_server_reply
                   ((sgxsd_msg_buf_t) { .data = NULL, .size = test_msg_buf.size }, &msg_from));
}
static void test_sgxsd_server_reply_rand_error(void **state) {
  sgxsd_msg_from_t msg_from = valid_msg_from;
  expect_sgx_read_rand(SGX_ERROR_UNEXPECTED, NULL, sizeof(((sgxsd_aes_gcm_iv_t*)0)->data));
  assert_int_equal(SGX_ERROR_UNEXPECTED, sgxsd_enclave_server_reply(test_msg_buf, &msg_from));
}
static void test_sgxsd_server_reply_encrypt_error(void **state) {
  test_sgxsd_server_reply(SGX_ERROR_UNEXPECTED, SGX_ERROR_UNEXPECTED, SGX_SUCCESS, SGX_SUCCESS, test_msg_buf, NULL);
}
static void test_sgxsd_server_reply_ocall_error(void **state) {
  test_sgxsd_server_reply(SGX_ERROR_UNEXPECTED, SGX_SUCCESS, SGX_ERROR_UNEXPECTED, SGX_SUCCESS, test_msg_buf, NULL);
  test_sgxsd_server_reply(SGX_ERROR_UNEXPECTED, SGX_SUCCESS, SGX_SUCCESS, SGX_ERROR_UNEXPECTED, test_msg_buf, NULL);
}
static void test_sgxsd_server_reply_empty(void **state) {
  test_sgxsd_server_reply(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, null_msg_buf, NULL);
  test_sgxsd_server_reply(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, empty_msg_buf, NULL);
}
static void test_sgxsd_server_reply_valid(void **state) {
  test_sgxsd_server_reply(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, test_msg_buf, NULL);
}
static void test_sgxsd_server_reply_twice(void **state) {
  sgxsd_msg_from_t msg_from = valid_msg_from;
  test_sgxsd_server_reply(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, test_msg_buf, &msg_from);

  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_reply(test_msg_buf, &msg_from));
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_noreply(&msg_from));
}

static void test_sgxsd_server_noreply_valid(void **state) {
  test_sgxsd_server_noreply(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, NULL);
}

static void test_sgxsd_server_noreply_twice(void **state) {
  sgxsd_msg_from_t msg_from = valid_msg_from;
  test_sgxsd_server_noreply(SGX_SUCCESS, SGX_SUCCESS, SGX_SUCCESS, &msg_from);
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_noreply(&msg_from));
  assert_int_equal(SGX_ERROR_INVALID_STATE, sgxsd_enclave_server_reply(test_msg_buf, &msg_from));
}

int main(int argc, char *argv[]) {
  UnitTest tests[] = {
    unit_test_setup(tests, setup_tests),

    // uninitialized node tests
    unit_test(test_sgxsd_get_next_report_node_uninitialized),
    unit_test(test_sgxsd_set_current_quote_node_uninitialized),
    unit_test(test_sgxsd_negotiate_request_node_uninitialized),
    unit_test(test_sgxsd_server_start_node_uninitialized),
    unit_test(test_sgxsd_server_call_node_uninitialized),
    unit_test(test_sgxsd_server_stop_node_uninitialized),

    // node init tests
    unit_test(test_sgxsd_node_init_rand_error),
    unit_test(test_sgxsd_node_init_null_args),
    unit_test(test_sgxsd_node_init_pending_requests_table_order_too_large),
    unit_test_setup(node_tests, test_sgxsd_node_init),
    unit_test(test_sgxsd_node_init_already_initialized),

    // get_next_report tests
    unit_test(test_sgxsd_get_next_report_null_report),

    // negotiate_request tests
    unit_test(test_sgxsd_negotiate_request_null_request),
    unit_test(test_sgxsd_negotiate_request_null_response),
    unit_test(test_sgxsd_negotiate_request_generate_keypair_rand_error),

    // server start tests
    unit_test(test_sgxsd_server_start_invalid_handle),
    unit_test_setup_teardown(test_sgxsd_server_start_already_started, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_server_start_init_error, test_noop, test_sgxsd_server_stop_already_stopped),
    unit_test_setup_teardown(test_sgxsd_server_start_valid, test_noop, test_sgxsd_server_stop_valid),

    // rate limit fingerprint tests
    unit_test_setup_teardown(test_sgxsd_ratelimit_fingerprint_golden_path, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_ratelimit_fingerprint_call_still_valid, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),

    // call tests
    unit_test_setup_teardown(test_sgxsd_server_call_invalid_request_id, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_server_call_invalid_handle, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test(test_sgxsd_server_call_not_started),
    unit_test_setup_teardown(test_sgxsd_server_call_empty, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_server_call_invalid_null_data, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_server_call_decrypt_msg_error, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_server_call_handler_error, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_server_call_valid, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),
    unit_test_setup_teardown(test_sgxsd_server_call_replay, test_sgxsd_server_start_valid, test_sgxsd_server_stop_valid),

    // server stop tests
    unit_test(test_sgxsd_server_stop_invalid_handle),
    unit_test(test_sgxsd_server_stop_already_stopped),
    unit_test_setup_teardown(test_sgxsd_server_stop_terminate_error, test_sgxsd_server_start_valid, test_sgxsd_server_stop_already_stopped),
    unit_test_setup_teardown(test_sgxsd_server_stop_valid, test_sgxsd_server_start_valid, test_sgxsd_server_stop_already_stopped),

    // reply tests
    unit_test(test_sgxsd_server_reply_invalid_buf),
    unit_test(test_sgxsd_server_reply_rand_error),
    unit_test(test_sgxsd_server_reply_encrypt_error),
    unit_test(test_sgxsd_server_reply_ocall_error),
    unit_test(test_sgxsd_server_reply_empty),
    unit_test(test_sgxsd_server_reply_valid),
    unit_test(test_sgxsd_server_reply_twice),
    unit_test(test_sgxsd_server_noreply_valid),
    unit_test(test_sgxsd_server_noreply_twice),
    unit_test_teardown(node_tests, teardown_node_tests),
    unit_test_teardown(tests, teardown_tests),
  };
  return run_tests(tests);
}

//
// private utils
//

void test_read_rand(void *dst, size_t size) {
  size_t dst_idx = 0;
  for (; dst_idx < size - 3; dst_idx += 4) {
    long int rand;
    mrand48_r(&test_drand48_data, &rand);
    *((uint32_t *) (dst + dst_idx)) = rand;
  }
  for (; dst_idx < size; dst_idx++) {
    long int rand;
    mrand48_r(&test_drand48_data, &rand);
    *((uint8_t *) (dst + dst_idx)) = rand;
  }
}

//
// mock stubs
//

void expect_sgx_read_rand(sgx_status_t res, unsigned char **p_rand, size_t expected_length_in_bytes) {
  expect_value(sgx_read_rand, length_in_bytes, expected_length_in_bytes);
  unsigned char *res_rand = NULL;
  if (res == SGX_SUCCESS) {
    res_rand = test_malloc(expected_length_in_bytes);
    test_read_rand(res_rand, expected_length_in_bytes);
  }
  if (p_rand != NULL) {
    *p_rand = res_rand;
  }
  will_return(sgx_read_rand, res_rand);
  will_return(sgx_read_rand, res);
}

sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes) {
  check_expected(length_in_bytes);
  assert_int_not_equal(rand, NULL);
  void *res_rand = (void *) mock();
  if (res_rand != NULL) {
    memcpy(rand, res_rand, length_in_bytes);
    test_free(res_rand);
  }
  return (sgx_status_t) mock();
}

void expect_sgxsd_aes_gcm_encrypt(sgx_status_t res,
                                  const sgxsd_aes_gcm_key_t *expected_p_key,
                                  void *expected_p_src, uint32_t expected_src_len, bool capture_src,
                                  void **pp_expected_dst,
                                  const sgxsd_aes_gcm_iv_t *expected_p_iv,
                                  const void *expected_p_aad, uint32_t expected_aad_len,
                                  sgxsd_aes_gcm_mac_t **pp_expected_out_mac) {
  uint8_t *res_p_dst = NULL;
  sgxsd_aes_gcm_mac_t *res_out_mac = NULL;
  if (res == SGX_SUCCESS) {
    if (expected_src_len != 0) {
      res_p_dst = test_malloc(expected_src_len);
    }
    res_out_mac = test_malloc(sizeof(*res_out_mac));
    test_read_rand(res_out_mac->data, sizeof(res_out_mac->data));
  }
  if (pp_expected_dst != NULL) {
    *pp_expected_dst = res_p_dst;
  }
  if (pp_expected_out_mac != NULL) {
    *pp_expected_out_mac = res_out_mac;
  }
  if (expected_p_key != NULL) {
    expect_memory(sgxsd_aes_gcm_encrypt, p_key, expected_p_key, sizeof(expected_p_key->data));
  } else {
    expect_not_value(sgxsd_aes_gcm_encrypt, p_key, NULL);
  }
  expect_value(sgxsd_aes_gcm_encrypt, src_len, expected_src_len);
  if (capture_src) {
    will_return(sgxsd_aes_gcm_encrypt, expected_p_src);
    expect_not_value(sgxsd_aes_gcm_encrypt, p_src, NULL);
  } else {
    will_return(sgxsd_aes_gcm_encrypt, NULL);
    if (expected_src_len != 0) {
      assert_int_not_equal(expected_p_src, NULL);
      expect_memory(sgxsd_aes_gcm_encrypt, p_src, expected_p_src, expected_src_len);
    } else {
      expect_any(sgxsd_aes_gcm_encrypt, p_src);
    }
  }
  will_return(sgxsd_aes_gcm_encrypt, res_p_dst);
  expect_memory(sgxsd_aes_gcm_encrypt, p_iv, expected_p_iv, sizeof(expected_p_iv->data));
  expect_value(sgxsd_aes_gcm_encrypt, aad_len, expected_aad_len);
  if (expected_aad_len != 0) {
    assert_int_not_equal(expected_p_aad, NULL);
    expect_memory(sgxsd_aes_gcm_encrypt, p_aad, expected_p_aad, expected_aad_len);
  } else {
    expect_any(sgxsd_aes_gcm_encrypt, p_aad);
  }
  will_return(sgxsd_aes_gcm_encrypt, res_out_mac);
  will_return(sgxsd_aes_gcm_encrypt, res);
}
sgx_status_t sgxsd_aes_gcm_encrypt(const sgxsd_aes_gcm_key_t *p_key,
				   const void *p_src, uint32_t src_len, void *p_dst,
				   const sgxsd_aes_gcm_iv_t *p_iv,
                                   const void *p_aad, uint32_t aad_len,
                                   sgxsd_aes_gcm_mac_t *p_out_mac) {
  check_expected(p_key);
  check_expected(src_len);
  void *res_p_src = (void *) mock();
  if (res_p_src != NULL) {
    assert_int_not_equal(p_src, NULL);
    memcpy(res_p_src, p_src, src_len);
  }
  check_expected(p_src);
  void *res_p_dst = (void *) mock();
  if (res_p_dst != NULL) {
    assert_int_not_equal(p_dst, NULL);
    assert_int_not_equal(p_src, NULL);
    memcpy(p_dst, res_p_dst, src_len);
    test_free(res_p_dst);
  }
  check_expected(p_iv);
  check_expected(aad_len);
  check_expected(p_aad);
  assert_int_not_equal(p_out_mac, NULL);
  sgxsd_aes_gcm_mac_t *res_p_out_mac = (sgxsd_aes_gcm_mac_t *) mock();
  if (res_p_out_mac != NULL) {
    memcpy(p_out_mac, res_p_out_mac, sizeof(*p_out_mac));
    test_free(res_p_out_mac);
  }
  
  return (sgx_status_t) mock();
}

void expect_sgxsd_aes_gcm_decrypt(sgx_status_t res,
                                  const sgxsd_aes_gcm_key_t *expected_p_key,
                                  const void *expected_p_src, uint32_t expected_src_len,
                                  void **pp_expected_dst,
                                  const sgxsd_aes_gcm_iv_t *expected_p_iv,
                                  const void *expected_p_aad, uint32_t expected_aad_len,
                                  const sgxsd_aes_gcm_mac_t *expected_p_in_mac) {
  uint8_t *res_p_dst = NULL;
  if (res == SGX_SUCCESS) {
    if (expected_src_len != 0) {
      res_p_dst = test_malloc(expected_src_len);
    }
  }
  if (pp_expected_dst != NULL) {
    *pp_expected_dst = res_p_dst;
  }
  if (expected_p_key != NULL) {
    expect_memory(sgxsd_aes_gcm_decrypt, p_key, expected_p_key, sizeof(expected_p_key->data));
  } else {
    expect_not_value(sgxsd_aes_gcm_decrypt, p_key, NULL);
  }
  expect_value(sgxsd_aes_gcm_decrypt, src_len, expected_src_len);
  if (expected_src_len != 0) {
    assert_int_not_equal(expected_p_src, NULL);
    expect_memory(sgxsd_aes_gcm_decrypt, p_src, expected_p_src, expected_src_len);
  } else {
    expect_any(sgxsd_aes_gcm_decrypt, p_src);
  }
  will_return(sgxsd_aes_gcm_decrypt, res_p_dst);
  expect_memory(sgxsd_aes_gcm_decrypt, p_iv, expected_p_iv, sizeof(expected_p_iv->data));
  expect_value(sgxsd_aes_gcm_decrypt, aad_len, expected_aad_len);
  if (expected_aad_len != 0) {
    assert_int_not_equal(expected_p_aad, NULL);
    expect_memory(sgxsd_aes_gcm_decrypt, p_aad, expected_p_aad, expected_aad_len);
  } else {
    expect_any(sgxsd_aes_gcm_decrypt, p_aad);
  }
  expect_memory(sgxsd_aes_gcm_decrypt, p_in_mac, expected_p_in_mac, sizeof(expected_p_in_mac->data));
  will_return(sgxsd_aes_gcm_decrypt, res);
}
sgx_status_t sgxsd_aes_gcm_decrypt(const sgxsd_aes_gcm_key_t *p_key,
				   const void *p_src, uint32_t src_len, void *p_dst,
				   const sgxsd_aes_gcm_iv_t *p_iv,
                                   const void *p_aad, uint32_t aad_len,
                                   const sgxsd_aes_gcm_mac_t *p_in_mac) {
  check_expected(p_key);
  check_expected(src_len);
  check_expected(p_src);
  void *res_p_dst = (void *) mock();
  if (res_p_dst != NULL) {
    assert_int_not_equal(p_dst, NULL);
    assert_int_not_equal(p_src, NULL);
    memcpy(p_dst, res_p_dst, src_len);
    test_free(res_p_dst);
  }
  check_expected(p_iv);
  check_expected(aad_len);
  check_expected(p_aad);
  check_expected(p_in_mac);

  return (sgx_status_t) mock();
}

void expect_sgxsd_ocall_reply(sgx_status_t ocall_res, sgx_status_t res,
                              const void *p_expected_dst, size_t expected_reply_data_size,
                              const void *expected_iv, size_t expected_iv_len,
                              const sgxsd_aes_gcm_mac_t *p_expected_out_mac,
                              uint64_t expected_tag) {
  expect_value(sgxsd_ocall_reply, reply_data_size, expected_reply_data_size);
  if (expected_reply_data_size != 0) {
    assert_int_not_equal(p_expected_dst, NULL);
    expect_memory(sgxsd_ocall_reply, reply_data, p_expected_dst, expected_reply_data_size);
  } else {
    expect_any(sgxsd_ocall_reply, reply_data);
  }
  expect_not_value(sgxsd_ocall_reply, reply_header, NULL);
  expect_memory(sgxsd_ocall_reply, reply_header->iv.data, expected_iv, expected_iv_len);
  expect_memory(sgxsd_ocall_reply, reply_header->mac.data, p_expected_out_mac, sizeof(p_expected_out_mac->data));
  expect_value(sgxsd_ocall_reply, msg_tag.tag, expected_tag);
  will_return(sgxsd_ocall_reply, res);
  will_return(sgxsd_ocall_reply, ocall_res);
}

void expect_sgxsd_ocall_noreply(sgx_status_t ocall_res, sgx_status_t res, uint64_t expected_tag) {
  expect_value(sgxsd_ocall_reply, reply_data_size, 0);
  expect_value(sgxsd_ocall_reply, reply_data, NULL);
  expect_value(sgxsd_ocall_reply, reply_header, NULL);
  expect_value(sgxsd_ocall_reply, msg_tag.tag, expected_tag);
  will_return(sgxsd_ocall_reply, res);
  will_return(sgxsd_ocall_reply, ocall_res);
}

sgx_status_t sgxsd_ocall_reply(sgx_status_t* retval, const sgxsd_msg_header_t *reply_header,
                               const uint8_t *reply_data, size_t reply_data_size,
                               sgxsd_msg_tag_t msg_tag) {
  check_expected(reply_data_size);
  check_expected(reply_data);
  check_expected(reply_header);
  if (reply_header != NULL) {
    check_expected(reply_header->iv.data);
    check_expected(reply_header->mac.data);
  }
  check_expected(msg_tag.tag);
  *retval = (sgx_status_t) mock();
  return (sgx_status_t) mock();
}
sgx_status_t sgxsd_ocall_ra_get_quote(sgx_status_t* retval,
                                      sgx_report_t report, sgx_quote_nonce_t nonce,
                                      const void *vp_get_quote_args,
                                      sgx_report_t* p_qe_report, sgx_quote_t* p_quote, uint32_t quote_size) {
  *retval = (sgx_status_t) mock();
  return (sgx_status_t) mock();
}

int sgx_is_outside_enclave(const void *addr, size_t size) {
  return (int) mock();
}

uint32_t sgx_spin_lock(sgx_spinlock_t *lock) {
  return 0;
}
uint32_t sgx_spin_unlock(sgx_spinlock_t *lock) {
  return 0;
}

void br_sha256_init(br_sha256_context *sha_context) {
}

void br_sha256_update(br_sha256_context *sha_context, const void *p_src, size_t src_len) {
}

void br_sha256_out(const br_sha256_context *sha_handle, void *p_hash) {
}

sgx_status_t sgx_sha256_close(sgx_sha_state_handle_t sha_handle) {
  return (sgx_status_t) SGX_SUCCESS;
}

sgx_status_t sgx_create_report(const sgx_target_info_t *target_info, const sgx_report_data_t *report_data, sgx_report_t *report) {
  return (sgx_status_t) SGX_SUCCESS;
}

sgx_status_t sgx_verify_report(const sgx_report_t *report) {
  return (sgx_status_t) SGX_SUCCESS;
}

void expect_sgxsd_enclave_server_init(sgx_status_t res, void *expected_args, size_t expected_args_size) {
  expect_memory(sgxsd_enclave_server_init, args, expected_args, expected_args_size);
  expect_not_value(sgxsd_enclave_server_init, vpp_state, NULL);
  will_return(sgxsd_enclave_server_init, res);
}
sgx_status_t sgxsd_enclave_server_init(const sgxsd_server_init_args_t *args, sgxsd_server_state_t **vpp_state) {
  check_expected(args);
  check_expected(vpp_state);
  return (sgx_status_t) mock();
}

void expect_sgxsd_enclave_server_handle_call(sgx_status_t res, sgxsd_server_handle_call_args_t *expected_args,
                                             sgxsd_msg_buf_t expected_msg, sgxsd_msg_from_t expected_from) {
  expect_value(sgxsd_enclave_server_handle_call, args->query_phone_count, expected_args->query_phone_count);
  expect_memory(sgxsd_enclave_server_handle_call, args->query.iv.data, expected_args->query.iv.data, sizeof(expected_args->query.iv));
  expect_memory(sgxsd_enclave_server_handle_call, args->query.mac.data, expected_args->query.mac.data, sizeof(expected_args->query.mac));
  expect_value(sgxsd_enclave_server_handle_call, args->query.size, expected_args->query.size);
  expect_memory(sgxsd_enclave_server_handle_call, args->query.data, expected_args->query.data, expected_args->query.size);
  expect_memory(sgxsd_enclave_server_handle_call, args->query_commitment, expected_args->query_commitment, sizeof(expected_args->query_commitment));

  expect_value(sgxsd_enclave_server_handle_call, msg.size, expected_msg.size);
  if (expected_msg.size != 0) {
    assert_int_not_equal(expected_msg.data, NULL);
    expect_memory(sgxsd_enclave_server_handle_call, msg.data, expected_msg.data, expected_msg.size);
  } else {
    expect_any(sgxsd_enclave_server_handle_call, msg.data);
  }
  expect_memory(sgxsd_enclave_server_handle_call, &from.tag, &expected_from.tag, sizeof(expected_from.tag));
  expect_not_value(sgxsd_enclave_server_handle_call, vpp_state, NULL);
  will_return(sgxsd_enclave_server_handle_call, res);
}
sgx_status_t sgxsd_enclave_server_handle_call(const sgxsd_server_handle_call_args_t *args, sgxsd_msg_buf_t msg,
                                              sgxsd_msg_from_t from, sgxsd_server_state_t **vpp_state) {
  check_expected(args->query_phone_count);
  check_expected(args->query.iv.data);
  check_expected(args->query.mac.data);
  check_expected(args->query.size);
  check_expected(args->query.data);
  check_expected(args->query_commitment);

  check_expected(msg.size);
  check_expected(msg.data);
  check_expected(&from.tag);
  check_expected(vpp_state);
  return (sgx_status_t) mock();
}

void expect_sgxsd_enclave_create_ratelimit_fingerprint(sgx_status_t res,
                                                       uint8_t expected_fingerprint_key[32],
                                                       const sgxsd_server_handle_call_args_t *expected_args,
                                                       sgxsd_msg_buf_t expected_msg,
                                                       sgxsd_msg_from_t expected_from,
                                                       size_t expected_fingerprint_size) {
    expect_memory(sgxsd_enclave_create_ratelimit_fingerprint, fingerprint_key, expected_fingerprint_key, 32);

    expect_value(sgxsd_enclave_create_ratelimit_fingerprint, args->query_phone_count, expected_args->query_phone_count);
    expect_memory(sgxsd_enclave_create_ratelimit_fingerprint, args->query.iv.data, expected_args->query.iv.data,
                  sizeof(expected_args->query.iv));
    expect_memory(sgxsd_enclave_create_ratelimit_fingerprint, args->query.mac.data, expected_args->query.mac.data,
                  sizeof(expected_args->query.mac));
    expect_value(sgxsd_enclave_create_ratelimit_fingerprint, args->query.size, expected_args->query.size);
    expect_memory(sgxsd_enclave_create_ratelimit_fingerprint, args->query.data, expected_args->query.data,
                  expected_args->query.size);
    expect_memory(sgxsd_enclave_create_ratelimit_fingerprint, args->query_commitment, expected_args->query_commitment,
                  sizeof(expected_args->query_commitment));

    expect_value(sgxsd_enclave_create_ratelimit_fingerprint, msg.size, expected_msg.size);
    if (expected_msg.size != 0) {
        assert_int_not_equal(expected_msg.data, NULL);
        expect_memory(sgxsd_enclave_create_ratelimit_fingerprint, msg.data, expected_msg.data, expected_msg.size);
    } else {
        expect_any(sgxsd_enclave_create_ratelimit_fingerprint, msg.data);
    }
    expect_memory(sgxsd_enclave_create_ratelimit_fingerprint, &from.tag, &expected_from.tag, sizeof(expected_from.tag));

    expect_value(sgxsd_enclave_create_ratelimit_fingerprint, fingerprint_size, expected_fingerprint_size);

    will_return(sgxsd_enclave_create_ratelimit_fingerprint, res);
}

sgx_status_t sgxsd_enclave_create_ratelimit_fingerprint(uint8_t fingerprint_key[32],
                                                        const sgxsd_server_handle_call_args_t *args,
                                                        sgxsd_msg_buf_t msg,
                                                        sgxsd_msg_from_t from,
                                                        uint8_t *fingerprint,
                                                        size_t fingerprint_size) {
    check_expected(fingerprint_key);
    check_expected(args->query_phone_count);
    check_expected(args->query.iv.data);
    check_expected(args->query.mac.data);
    check_expected(args->query.size);
    check_expected(args->query.data);
    check_expected(args->query_commitment);

    check_expected(msg.size);
    check_expected(msg.data);
    check_expected(&from.tag);
    check_expected(fingerprint_size);

    return (sgx_status_t) mock();
}


void expect_sgxsd_enclave_server_terminate(sgx_status_t res, void *expected_args, size_t expected_args_size) {
  expect_memory(sgxsd_enclave_server_terminate, args, expected_args, expected_args_size);
  expect_any(sgxsd_enclave_server_terminate, vp_state);
  will_return(sgxsd_enclave_server_terminate, res);
}
sgx_status_t sgxsd_enclave_server_terminate(const sgxsd_server_terminate_args_t *args, sgxsd_server_state_t *vp_state) {
  check_expected(args);
  check_expected(vp_state);
  return (sgx_status_t) mock();
}
