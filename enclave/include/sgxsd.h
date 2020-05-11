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
#ifndef _SGXSD_H
#define _SGXSD_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>

#include "sgx_urts.h"
#include "sgx_quote.h"

//
// types
//

#define SGXSD_AES_GCM_IV_SIZE     12
#define SGXSD_AES_GCM_MAC_SIZE    16
#define SGXSD_AES_GCM_KEY_SIZE    32
#define SGXSD_CURVE25519_KEY_SIZE 32
#define SGXSD_SHA256_HASH_SIZE    32

typedef struct sgxsd_aes_gcm_mac {
  uint8_t data[SGXSD_AES_GCM_MAC_SIZE];
} sgxsd_aes_gcm_mac_t;
_Static_assert(sizeof(sgxsd_aes_gcm_mac_t) == SGXSD_AES_GCM_MAC_SIZE, "Enclave ABI compatibility");

typedef struct sgxsd_aes_gcm_iv {
  uint8_t data[SGXSD_AES_GCM_IV_SIZE];
} sgxsd_aes_gcm_iv_t;
_Static_assert(sizeof(sgxsd_aes_gcm_iv_t) == SGXSD_AES_GCM_IV_SIZE, "Enclave ABI compatibility");

typedef struct sgxsd_aes_gcm_key {
  uint8_t data[SGXSD_AES_GCM_KEY_SIZE];
} sgxsd_aes_gcm_key_t;
_Static_assert(sizeof(sgxsd_aes_gcm_key_t) == SGXSD_AES_GCM_KEY_SIZE, "Enclave ABI compatibility");

typedef struct sgxsd_curve25519_public_key {
  uint8_t x[SGXSD_CURVE25519_KEY_SIZE];
} sgxsd_curve25519_public_key_t;
_Static_assert(sizeof(sgxsd_curve25519_public_key_t) == SGXSD_CURVE25519_KEY_SIZE, "Enclave ABI compatibility");

typedef struct sgxsd_request_negotiation_request {
  sgxsd_curve25519_public_key_t client_pubkey;
} sgxsd_request_negotiation_request_t;
_Static_assert(sizeof(sgxsd_request_negotiation_request_t) == sizeof(sgxsd_curve25519_public_key_t), "Enclave ABI compatibility");

typedef struct sgxsd_pending_request_id {
  uint8_t data[sizeof(uint64_t)];
  sgxsd_aes_gcm_iv_t iv;
  sgxsd_aes_gcm_mac_t mac;
} sgxsd_pending_request_id_t;
_Static_assert(sizeof(sgxsd_pending_request_id_t) == sizeof(uint64_t) + sizeof(sgxsd_aes_gcm_iv_t) + sizeof(sgxsd_aes_gcm_mac_t), "Enclave ABI compatibility");

typedef struct sgxsd_request_negotiation_response {
  sgxsd_curve25519_public_key_t server_static_pubkey;
  sgxsd_curve25519_public_key_t server_ephemeral_pubkey;
  struct {
    uint8_t data[sizeof(sgxsd_pending_request_id_t)];
    sgxsd_aes_gcm_iv_t iv;
    sgxsd_aes_gcm_mac_t mac;
  } encrypted_pending_request_id;
} sgxsd_request_negotiation_response_t;
_Static_assert(sizeof(sgxsd_request_negotiation_response_t) == sizeof(sgxsd_curve25519_public_key_t) * 2 + sizeof(sgxsd_pending_request_id_t) + sizeof(sgxsd_aes_gcm_iv_t) + sizeof(sgxsd_aes_gcm_mac_t), "Enclave ABI compatibility");

typedef struct sgxsd_msg_tag {
    union {
        void *p_tag;
        uint64_t tag;
    };
} sgxsd_msg_tag_t;
_Static_assert(sizeof(sgxsd_msg_tag_t) == sizeof(uint64_t), "Enclave ABI compatibility");

typedef struct sgxsd_msg_header {
  sgxsd_aes_gcm_iv_t iv;
  sgxsd_aes_gcm_mac_t mac;
  sgxsd_pending_request_id_t pending_request_id;
} sgxsd_msg_header_t;
_Static_assert(sizeof(sgxsd_msg_header_t) == sizeof(sgxsd_aes_gcm_iv_t) + sizeof(sgxsd_aes_gcm_mac_t) + sizeof(sgxsd_pending_request_id_t), "Enclave ABI compatibility");

typedef struct sgxsd_node_init_args {
  uint8_t pending_requests_table_order;
} sgxsd_node_init_args_t;

typedef uint64_t sgxsd_server_state_handle_t;

//
// public api (untrusted)
//

#define sgxsd_status_ok() (sgxsd_status_t) { .ok = true, .name = "ok", .code = 0 }
#define sgxsd_status_error(Name) (sgxsd_status_t) { .ok = false, .name = Name, .code = 0 }
#define sgxsd_status_error_code(Name, SgxStatus) (sgxsd_status_t) { .ok = false, .name = Name, .code = SgxStatus }
typedef struct sgxsd_status {
    bool ok;
    const char *name;
    int64_t code;
} sgxsd_status_t;

typedef struct sgxsd_enclave {
    sgx_enclave_id_t id;
    union {
        sgx_epid_group_id_t gid;
        uint32_t gid32;
    };
    sgx_launch_token_t launch_token;
} sgxsd_enclave_t;

typedef sgxsd_status_t (*sgxsd_start_callback_t)(sgxsd_enclave_t, va_list);
sgxsd_status_t sgxsd_start(const char *enclave_path, bool debug, const sgxsd_node_init_args_t *p_node_init_args, sgxsd_start_callback_t p_callback, ...);
sgxsd_status_t sgxsd_get_next_quote(sgx_enclave_id_t enclave_id, sgx_spid_t spid, const uint8_t *p_sig_rl, uint32_t sig_rl_size, sgx_quote_t *p_quote, uint32_t quote_size);

//
// error codes
//

typedef enum sgxsd_status_code {
  SGXSD_ERROR_PENDING_REQUEST_NOT_FOUND = SGX_MK_ERROR(0x10001),
} sgxsd_status_code_t;

#endif
