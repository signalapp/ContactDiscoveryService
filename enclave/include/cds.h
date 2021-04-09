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
#ifndef _CDS_H
#define _CDS_H

#include <stdint.h>
#include <stdlib.h>

#include "sgx_error.h"
#include "sgxsd.h"
#include "cds-enclave-hash.h"

#ifndef CDS_MAX_HASH_TABLE_ORDER
#define CDS_MAX_HASH_TABLE_ORDER 13
#endif

typedef struct cds_encrypted_msg {
    sgxsd_aes_gcm_iv_t iv;
    sgxsd_aes_gcm_mac_t mac;
    uint32_t size;
    uint8_t *data;
} cds_encrypted_msg_t;
_Static_assert(sizeof(cds_encrypted_msg_t) == sizeof(sgxsd_aes_gcm_iv_t) + sizeof(sgxsd_aes_gcm_mac_t) + sizeof(uint32_t) + sizeof(uint8_t *), "Enclave ABI compatibility");

typedef struct sgxsd_server_init_args {
    uint32_t max_query_phones;
    uint32_t max_ratelimit_states;
} sgxsd_server_init_args_t, cds_start_args_t;
_Static_assert(sizeof(cds_start_args_t) == sizeof(uint32_t) + sizeof(uint32_t), "Enclave ABI compatibility");

typedef struct sgxsd_server_handle_call_args {
    uint32_t query_phone_count;
    uint32_t ratelimit_state_size;
    uuid_t   ratelimit_state_uuid;
    uint8_t *ratelimit_state_data;
    cds_encrypted_msg_t query;
    uint8_t  query_commitment[SGXSD_SHA256_HASH_SIZE];
} sgxsd_server_handle_call_args_t, cds_call_args_t;
_Static_assert(sizeof(cds_call_args_t) == sizeof(uint32_t) + sizeof(uint32_t) + sizeof(cds_encrypted_msg_t) + SGXSD_SHA256_HASH_SIZE + sizeof(uuid_t) + sizeof(uint8_t *), "Enclave ABI compatibility");

typedef struct sgxsd_server_terminate_args {
    const phone_t* in_phones;
    size_t in_phone_count;
    const uuid_t* in_uuids;
} sgxsd_server_terminate_args_t, cds_stop_args_t;
_Static_assert(sizeof(cds_stop_args_t) == sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t), "Enclave ABI compatibility");

//
// error codes
//

typedef enum cds_status_code {
    CDS_ERROR_INVALID_REQUEST_SIZE      = SGX_MK_ERROR(0x20001),
    CDS_ERROR_QUERY_COMMITMENT_MISMATCH = SGX_MK_ERROR(0x20002),
} cds_status_code_t;

#endif
