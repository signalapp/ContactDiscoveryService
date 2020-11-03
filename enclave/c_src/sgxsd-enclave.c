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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <x86intrin.h>

#include "sgx_trts.h"
#include "sgx_quote.h"
#include "sgx_utils.h"
#include "sgx_spinlock.h"
#include "sgx_lfence.h"

#include "bearssl_aead.h"
#include "bearssl_hash.h"

#include "cds.h"
#include "sgxsd-enclave.h"

#if UNIT_TESTING
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmockery.h"
#define memset_s(s, smax, c, n) memset(s, c, n);
#endif

//
// internal definitions
//

typedef struct sgxsd_sha256_hash {
  uint8_t data[SGXSD_SHA256_HASH_SIZE];
} sgxsd_sha256_hash_t;

typedef struct sgxsd_pending_request {
    uint64_t id_val;
    sgxsd_sha256_hash_t hkdf_prk;
} sgxsd_pending_request_t;

typedef struct sgxsd_server_state_desc {
    bool valid;
    sgx_spinlock_t lock;
    sgxsd_server_state_t *p_state;
} sgxsd_server_state_desc_t;

#ifndef SGXSD_ENCLAVE_MAX_SERVERS
#define SGXSD_ENCLAVE_MAX_SERVERS 256
#endif

sgx_status_t SGX_CDECL sgxsd_ocall_reply(sgx_status_t* retval, const sgxsd_msg_header_t* reply_header, const uint8_t* reply_data, size_t reply_data_size, sgxsd_msg_tag_t msg_tag);

sgx_status_t sgxsd_enclave_generate_curve25519_keypair(sgxsd_curve25519_key_pair_t *p_keypair);

//
// static variables
//

bool g_sgxsd_enclave_node_initialized = false;
sgx_spinlock_t g_sgxsd_enclave_node_init_lock;

sgxsd_sha256_hash_t g_sgxsd_enclave_read_rand_state;
sgx_spinlock_t g_sgxsd_enclave_read_rand_lock;

sgxsd_curve25519_key_pair_t g_sgxsd_enclave_dh_keypair;
sgxsd_curve25519_key_pair_t g_sgxsd_enclave_new_dh_keypair;
sgx_spinlock_t g_sgxsd_enclave_dh_keypair_lock;

sgxsd_pending_request_t *g_sgxsd_enclave_pending_requests;
uint8_t g_sgxsd_enclave_pending_requests_table_order;
uint64_t g_sgxsd_enclave_last_pending_request_id_val;
sgxsd_aes_gcm_key_t g_sgxsd_enclave_pending_request_id_key;
sgx_spinlock_t g_sgxsd_enclave_pending_requests_lock;

static const sgxsd_server_state_handle_t g_sgxsd_enclave_max_servers = SGXSD_ENCLAVE_MAX_SERVERS;
sgxsd_server_state_desc_t g_sgxsd_enclave_server_states[SGXSD_ENCLAVE_MAX_SERVERS];

static
void sgxsd_spin_lock(sgx_spinlock_t *p_spinlock) {
    sgx_spin_lock(p_spinlock);
    sgx_lfence();
}
static
void sgxsd_spin_unlock(sgx_spinlock_t *p_spinlock) {
    sgx_spin_unlock(p_spinlock);
}

sgx_status_t sgxsd_enclave_node_init_locked(const sgxsd_node_init_args_t *p_args);
sgx_status_t sgxsd_enclave_node_init(const sgxsd_node_init_args_t *p_args) {
    sgxsd_spin_lock(&g_sgxsd_enclave_node_init_lock);

    sgx_status_t res = sgxsd_enclave_node_init_locked(p_args);

    sgxsd_spin_unlock(&g_sgxsd_enclave_node_init_lock);
    return res;
}
sgx_status_t sgxsd_enclave_node_init_locked(const sgxsd_node_init_args_t *p_args) {
    if (g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }

    // don't allow enclave to be mapped at minimum or maximum of address space
    if (1 != sgx_is_outside_enclave(NULL, 0)) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (1 != sgx_is_outside_enclave((void *) UINTPTR_MAX, 0)) {
        return SGX_ERROR_UNEXPECTED;
    }

    // validate parameters
    if (p_args == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (p_args->pending_requests_table_order > sizeof(uint64_t) * 8 - 1) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate unpredictable initial value for private and public keys
    sgx_status_t dh_keypair_rand_res =
        sgxsd_enclave_generate_curve25519_keypair(&g_sgxsd_enclave_dh_keypair);
    if (dh_keypair_rand_res != SGX_SUCCESS) {
        return dh_keypair_rand_res;
    }

    sgx_status_t new_dh_keypair_rand_res =
        sgxsd_enclave_generate_curve25519_keypair(&g_sgxsd_enclave_new_dh_keypair);
    if (new_dh_keypair_rand_res != SGX_SUCCESS) {
        return new_dh_keypair_rand_res;
    }

    sgx_status_t pending_request_id_key_res =
        sgx_read_rand((uint8_t *) &g_sgxsd_enclave_pending_request_id_key.data, sizeof(g_sgxsd_enclave_pending_request_id_key.data));
    if (pending_request_id_key_res != SGX_SUCCESS) {
        return pending_request_id_key_res;
    }

    g_sgxsd_enclave_pending_requests_table_order = p_args->pending_requests_table_order;
    g_sgxsd_enclave_pending_requests = calloc((uint64_t){1} << g_sgxsd_enclave_pending_requests_table_order,
                                              sizeof(*g_sgxsd_enclave_pending_requests));
    if (g_sgxsd_enclave_pending_requests == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    g_sgxsd_enclave_node_initialized = true;
    return SGX_SUCCESS;
}

void __attribute__ ((noinline)) sgxsd_br_clear_stack() {
    uint8_t stack[4096];
    memset_s(&stack, sizeof(stack), 0, sizeof(stack));
    _mm256_zeroall();
}

#ifndef UNIT_TESTING
static
sgx_status_t sgxsd_aes_gcm_run(bool encrypt, const sgxsd_aes_gcm_key_t *p_key,
                               const void *p_src, uint32_t src_len, void *p_dst,
                               const sgxsd_aes_gcm_iv_t *p_iv,
                               const void *p_aad, uint32_t aad_len,
                               sgxsd_aes_gcm_mac_t *p_mac) {
    if (p_key == NULL ||
	((p_src == NULL || p_dst == NULL) && src_len != 0) ||
        p_iv == NULL ||
        (p_aad == NULL && aad_len != 0) ||
        p_mac == NULL) {
	return SGX_ERROR_INVALID_PARAMETER;
    }
    br_aes_x86ni_ctr_keys aes_ctx;
    br_aes_x86ni_ctr_init(&aes_ctx, p_key->data, sizeof(p_key->data));
    br_gcm_context aes_gcm_ctx;
    br_gcm_init(&aes_gcm_ctx, &aes_ctx.vtable, &br_ghash_pclmul);
    br_gcm_reset(&aes_gcm_ctx, p_iv->data, sizeof(p_iv->data));
    if (aad_len != 0) {
        br_gcm_aad_inject(&aes_gcm_ctx, p_aad, aad_len);
    }
    br_gcm_flip(&aes_gcm_ctx);
    if (src_len != 0) {
        memmove(p_dst, p_src, src_len);
        br_gcm_run(&aes_gcm_ctx, encrypt, p_dst, src_len);
    }
    bool tag_res;
    if (encrypt) {
      br_gcm_get_tag(&aes_gcm_ctx, p_mac->data);
      tag_res = true;
    } else {
      tag_res = br_gcm_check_tag(&aes_gcm_ctx, p_mac->data);
    }
    sgxsd_br_clear_stack();
    memset_s(&aes_ctx, sizeof(aes_ctx), 0, sizeof(aes_ctx));
    memset_s(&aes_gcm_ctx, sizeof(aes_gcm_ctx), 0, sizeof(aes_gcm_ctx));
    if (tag_res) {
        return SGX_SUCCESS;
    } else {
        if (p_dst != NULL) {
            memset_s(p_dst, src_len, 0, src_len);
        }
        return SGX_ERROR_MAC_MISMATCH;
    }
}

sgx_status_t sgxsd_aes_gcm_encrypt(const sgxsd_aes_gcm_key_t *p_key,
				   const void *p_src, uint32_t src_len, void *p_dst,
				   const sgxsd_aes_gcm_iv_t *p_iv,
                                   const void *p_aad, uint32_t aad_len,
                                   sgxsd_aes_gcm_mac_t *p_out_mac) {
    return sgxsd_aes_gcm_run(true, p_key, p_src, src_len, p_dst, p_iv, p_aad, aad_len, p_out_mac);
}
sgx_status_t sgxsd_aes_gcm_decrypt(const sgxsd_aes_gcm_key_t *p_key,
				   const void *p_src, uint32_t src_len, void *p_dst,
				   const sgxsd_aes_gcm_iv_t *p_iv,
                                   const void *p_aad, uint32_t aad_len,
                                   const sgxsd_aes_gcm_mac_t *p_in_mac) {
    return sgxsd_aes_gcm_run(false, p_key, p_src, src_len, p_dst, p_iv, p_aad, aad_len, (sgxsd_aes_gcm_mac_t *) p_in_mac);
}
#endif

typedef struct sgxsd_sha256_buf {
    const void *data;
    uint32_t size;
} sgxsd_sha256_buf_t;

static
void sgxsd_enclave_sha256(sgxsd_sha256_hash_t *p_hash, uint32_t buf_count, const sgxsd_sha256_buf_t *bufs) {
    br_sha256_context sha_context;
    br_sha256_init(&sha_context);
    for (uint32_t buf_idx = 0; buf_idx < buf_count; buf_idx++) {
        br_sha256_update(&sha_context, bufs[buf_idx].data, bufs[buf_idx].size);
    }
    br_sha256_out(&sha_context, p_hash->data);
    memset_s(&sha_context, sizeof(sha_context), 0, sizeof(sha_context));
}

void sgxsd_enclave_hmac_sha256(sgxsd_sha256_hash_t *p_hash, uint32_t buf_count, sgxsd_sha256_buf_t *bufs) {
    uint8_t i_key_pad[64];
    memset_s(i_key_pad, sizeof(i_key_pad), 0x36, sizeof(i_key_pad));
    uint8_t o_key_pad[64];
    memset_s(o_key_pad, sizeof(o_key_pad), 0x5c, sizeof(o_key_pad));

    sgxsd_sha256_buf_t *p_key_buf = &bufs[0];
    sgxsd_sha256_hash_t key_hash;
    if (p_key_buf->size > sizeof(i_key_pad)) {
        sgxsd_enclave_sha256(&key_hash, 1, p_key_buf);
        *p_key_buf = (sgxsd_sha256_buf_t) { .data = key_hash.data, .size = sizeof(key_hash.data) };
    }

    // after this point we need to make sure to zero-out i_key_pad and o_key_pad
    _Static_assert(sizeof(key_hash.data) <= sizeof(i_key_pad), "i_key_pad overflow");
    for (uint32_t key_idx = 0; key_idx < p_key_buf->size; key_idx++) {
        const uint8_t *key_bytes = p_key_buf->data;
        i_key_pad[key_idx] ^= key_bytes[key_idx];
        o_key_pad[key_idx] ^= key_bytes[key_idx];
    }
    memset_s(&key_hash, sizeof(key_hash), 0, sizeof(key_hash));

    *p_key_buf = (sgxsd_sha256_buf_t) { .data = i_key_pad, .size = sizeof(i_key_pad) };
    sgxsd_enclave_sha256(p_hash, buf_count, bufs);
    sgxsd_enclave_sha256(p_hash, 2, (sgxsd_sha256_buf_t[]) {
        { &o_key_pad, sizeof(o_key_pad) },
        { p_hash->data, sizeof(p_hash->data) }
    });

    sgxsd_br_clear_stack();
    memset_s(i_key_pad, sizeof(i_key_pad), 0, sizeof(i_key_pad));
    memset_s(o_key_pad, sizeof(o_key_pad), 0, sizeof(o_key_pad));
}
typedef struct sgxsd_ra_hkdf_buf {
    sgxsd_sha256_hash_t t_n;
    uint8_t n;
} sgxsd_ra_hkdf_buf_t;
void sgxsd_enclave_ra_hkdf_round(sgxsd_sha256_hash_t *prk, sgxsd_ra_hkdf_buf_t *buf) {
    buf->n++;
    sgxsd_sha256_buf_t hmac_data_buf;
    if (buf->n == 1) {
        hmac_data_buf = (sgxsd_sha256_buf_t) { &buf->n, sizeof(buf->n) };
    } else {
        _Static_assert(offsetof(sgxsd_ra_hkdf_buf_t, n) == sizeof(buf->t_n.data), "sgxsd_ra_hkdf_buf_t.n alignment");
        hmac_data_buf = (sgxsd_sha256_buf_t) { buf->t_n.data, sizeof(buf->t_n.data) + sizeof(buf->n) };
    }
    sgxsd_enclave_hmac_sha256(&buf->t_n, 2, (sgxsd_sha256_buf_t[]) {
        { prk->data, sizeof(prk->data) },
        hmac_data_buf
    });
}

sgx_status_t sgxsd_enclave_read_rand(sgxsd_rand_buf_t *p_privkey) {
    sgx_status_t read_rand_res = sgx_read_rand((uint8_t *) &p_privkey->x, sizeof(p_privkey->x));
    if (read_rand_res != SGX_SUCCESS) {
        return read_rand_res;
    }

    sgxsd_spin_lock(&g_sgxsd_enclave_read_rand_lock);

    sgxsd_sha256_hash_t hkdf_prk;
    sgxsd_enclave_hmac_sha256(&hkdf_prk, 2, (sgxsd_sha256_buf_t[]) {
        { &g_sgxsd_enclave_read_rand_state.data, sizeof(g_sgxsd_enclave_read_rand_state.data) },
        { &p_privkey->x, sizeof(p_privkey->x) },
    });

    sgxsd_ra_hkdf_buf_t hkdf_buf = { .n = 0 };
    sgxsd_enclave_ra_hkdf_round(&hkdf_prk, &hkdf_buf);
    g_sgxsd_enclave_read_rand_state = hkdf_buf.t_n;

    sgxsd_enclave_ra_hkdf_round(&hkdf_prk, &hkdf_buf);
    memcpy(&p_privkey->x, &hkdf_buf.t_n.data, sizeof(p_privkey->x));
    _Static_assert(sizeof(p_privkey->x) == sizeof(hkdf_buf.t_n.data), "p_privkey overflow");

    sgxsd_spin_unlock(&g_sgxsd_enclave_read_rand_lock);

    memset_s(&hkdf_buf, sizeof(hkdf_buf), 0, sizeof(hkdf_buf));
    memset_s(&hkdf_prk, sizeof(hkdf_prk), 0, sizeof(hkdf_prk));

    return SGX_SUCCESS;
}

int curve25519_donna(uint8_t *, const uint8_t *, const uint8_t *);

sgx_status_t sgxsd_enclave_generate_curve25519_keypair(sgxsd_curve25519_key_pair_t *p_keypair) {
    // generate curve25519 private key
    sgx_status_t gen_privkey_res = sgxsd_enclave_read_rand(&p_keypair->privkey);
    if (gen_privkey_res != SGX_SUCCESS) {
        return gen_privkey_res;
    }
    p_keypair->privkey.x[0] &= 248;
    p_keypair->privkey.x[31] &= 127;
    p_keypair->privkey.x[31] |= 64;

    // compute curve25519 public key
    static const sgxsd_curve25519_public_key_t BASEPOINT = {{9}};
    curve25519_donna(p_keypair->pubkey.x, p_keypair->privkey.x, BASEPOINT.x);

    return SGX_SUCCESS;
}

sgx_status_t sgxsd_enclave_get_next_report(sgx_target_info_t qe_target_info, sgx_report_t *p_report) {
    if (!g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }

    // validate parameters
    if (p_report == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate curve25519
    sgxsd_curve25519_key_pair_t new_dh_keypair;
    sgx_status_t generate_keypair_res = sgxsd_enclave_generate_curve25519_keypair(&new_dh_keypair);
    if (generate_keypair_res != SGX_SUCCESS) {
        return generate_keypair_res;
    }

    // construct report data with new curve25519 public key
    sgx_report_data_t report_data = { .d = { 0 } };
    memcpy(report_data.d, new_dh_keypair.pubkey.x, sizeof(new_dh_keypair.pubkey.x));
    _Static_assert(sizeof(report_data.d) >= sizeof(new_dh_keypair.pubkey.x), "sgx_report_data_t.d overflow");

    sgx_status_t create_report_res = sgx_create_report(&qe_target_info, &report_data, p_report);
    if (create_report_res != SGX_SUCCESS) {
        // no need to cleanup new_dh_keypair as a report hasn't been generated to make it useful
        return create_report_res;
    }

    // move new keypair to transitional global variable
    sgxsd_spin_lock(&g_sgxsd_enclave_dh_keypair_lock);
    g_sgxsd_enclave_new_dh_keypair = new_dh_keypair;
    sgxsd_spin_unlock(&g_sgxsd_enclave_dh_keypair_lock);
    memset_s(&new_dh_keypair, sizeof(new_dh_keypair), 0, sizeof(new_dh_keypair));

    return SGX_SUCCESS;
}

sgx_status_t sgxsd_enclave_set_current_quote() {
    if (!g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }

    // copy new keypair to permanent global variable
    sgxsd_spin_lock(&g_sgxsd_enclave_dh_keypair_lock);
    g_sgxsd_enclave_dh_keypair = g_sgxsd_enclave_new_dh_keypair;
    sgxsd_spin_unlock(&g_sgxsd_enclave_dh_keypair_lock);

    return SGX_SUCCESS;
}

sgx_status_t sgxsd_enclave_add_pending_request(sgxsd_pending_request_id_t *p_pending_request_id, const sgxsd_pending_request_t *p_pending_request) {
    uint64_t pending_request_count_mask = ((uint64_t){1} << g_sgxsd_enclave_pending_requests_table_order) - 1;

    sgxsd_spin_lock(&g_sgxsd_enclave_pending_requests_lock);

    g_sgxsd_enclave_last_pending_request_id_val += 1;
    uint64_t pending_request_id_val = g_sgxsd_enclave_last_pending_request_id_val;
    sgxsd_pending_request_t *p_pending_requests_entry = &g_sgxsd_enclave_pending_requests[pending_request_id_val & pending_request_count_mask];
    p_pending_requests_entry->id_val = pending_request_id_val;
    memcpy(&p_pending_requests_entry->hkdf_prk, &p_pending_request->hkdf_prk, sizeof(p_pending_requests_entry->hkdf_prk));
    _Static_assert(sizeof(p_pending_requests_entry->hkdf_prk) == sizeof(p_pending_request->hkdf_prk), "overflow");

    sgxsd_spin_unlock(&g_sgxsd_enclave_pending_requests_lock);

    sgx_status_t iv_rand_res = sgx_read_rand((uint8_t *) &p_pending_request_id->iv, sizeof(p_pending_request_id->iv));
    if (iv_rand_res != SGX_SUCCESS) {
        return iv_rand_res;
    }

    sgx_status_t encrypt_res =
        sgxsd_aes_gcm_encrypt(&g_sgxsd_enclave_pending_request_id_key, /* p_key */
                              &pending_request_id_val, sizeof(pending_request_id_val), /* p_src, src_len */
                              &p_pending_request_id->data, /* p_dst */
                              &p_pending_request_id->iv, /* p_iv */
                              NULL, 0, /* p_aad, aad_len */
                              &p_pending_request_id->mac /* p_out_mac */);
    _Static_assert(sizeof(pending_request_id_val) == sizeof(p_pending_request_id->data), "pending_request_id overflow");
    if (encrypt_res != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

sgx_status_t sgxsd_enclave_get_pending_request(const sgxsd_pending_request_id_t *p_pending_request_id, sgxsd_pending_request_t *p_pending_request) {
    uint64_t pending_request_id_val = 0;
    sgx_status_t decrypt_res =
            sgxsd_aes_gcm_decrypt(&g_sgxsd_enclave_pending_request_id_key, /* p_key */
                                  &p_pending_request_id->data, sizeof(p_pending_request_id->data), /* p_src, src_len */
                                  &pending_request_id_val, /* p_dst */
                                  &p_pending_request_id->iv, /* p_iv */
                                  NULL, 0, /* p_aad, aad_len */
                                  &p_pending_request_id->mac /* p_in_mac */);
    _Static_assert(sizeof(p_pending_request_id->data) == sizeof(pending_request_id_val), "pending_request_id_val overflow");
    if (decrypt_res != SGX_SUCCESS) {
        return decrypt_res;
    }

    sgxsd_spin_lock(&g_sgxsd_enclave_pending_requests_lock);
    uint64_t pending_request_count_mask = ((uint64_t){1} << g_sgxsd_enclave_pending_requests_table_order) - 1;
    sgxsd_pending_request_t *p_found_pending_request =
            &g_sgxsd_enclave_pending_requests[pending_request_id_val & pending_request_count_mask];

    sgx_status_t res;
    if (p_found_pending_request->id_val == pending_request_id_val) {
        *p_pending_request = *p_found_pending_request;
        res = SGX_SUCCESS;
    } else {
        res = SGXSD_ERROR_PENDING_REQUEST_NOT_FOUND;
    }

    sgxsd_spin_unlock(&g_sgxsd_enclave_pending_requests_lock);
    return res;
}

sgx_status_t sgxsd_enclave_remove_pending_request(const sgxsd_pending_request_id_t *p_pending_request_id, sgxsd_pending_request_t *p_pending_request) {
    uint64_t pending_request_id_val = 0;
    sgx_status_t decrypt_res =
        sgxsd_aes_gcm_decrypt(&g_sgxsd_enclave_pending_request_id_key, /* p_key */
                              &p_pending_request_id->data, sizeof(p_pending_request_id->data), /* p_src, src_len */
                              &pending_request_id_val, /* p_dst */
                              &p_pending_request_id->iv, /* p_iv */
                              NULL, 0, /* p_aad, aad_len */
                              &p_pending_request_id->mac /* p_in_mac */);
    _Static_assert(sizeof(p_pending_request_id->data) == sizeof(pending_request_id_val), "pending_request_id_val overflow");
    if (decrypt_res != SGX_SUCCESS) {
        return decrypt_res;
    }

    sgxsd_spin_lock(&g_sgxsd_enclave_pending_requests_lock);
    uint64_t pending_request_count_mask = ((uint64_t){1} << g_sgxsd_enclave_pending_requests_table_order) - 1;
    sgxsd_pending_request_t *p_found_pending_request =
            &g_sgxsd_enclave_pending_requests[pending_request_id_val & pending_request_count_mask];

    sgx_status_t res;
    if (p_found_pending_request->id_val == pending_request_id_val) {
        *p_pending_request = *p_found_pending_request;
        memset_s(p_found_pending_request, sizeof(*p_found_pending_request), 0, sizeof(*p_found_pending_request));
        res = SGX_SUCCESS;
    } else {
        res = SGXSD_ERROR_PENDING_REQUEST_NOT_FOUND;
    }

    sgxsd_spin_unlock(&g_sgxsd_enclave_pending_requests_lock);
    return res;
}

void sgxsd_enclave_derive_request_keys(sgxsd_pending_request_t *p_pending_request,
                                       sgxsd_aes_gcm_key_t *p_client_key, sgxsd_aes_gcm_key_t *p_server_key) {
    // generate subkeys using HKDF(PRK)
    // HKDF T(1) = client sending AES-GCM key
    sgxsd_ra_hkdf_buf_t hkdf_buf = { .n = 0 };
    sgxsd_enclave_ra_hkdf_round(&p_pending_request->hkdf_prk, &hkdf_buf);
    if (p_client_key != NULL) {
        memmove(p_client_key->data, hkdf_buf.t_n.data, sizeof(p_client_key->data));
        _Static_assert(sizeof(p_client_key->data) <= sizeof(hkdf_buf.t_n.data), "AES key smaller than HKDF output size");
    }

    // HKDF T(2) = client receiving AES-GCM key
    sgxsd_enclave_ra_hkdf_round(&p_pending_request->hkdf_prk, &hkdf_buf);
    if (p_server_key != NULL) {
        memmove(p_server_key->data, hkdf_buf.t_n.data, sizeof(p_server_key->data));
        _Static_assert(sizeof(p_server_key->data) <= sizeof(hkdf_buf.t_n.data), "AES key smaller than HKDF output size");
    }

    // erase HKDF state
    memset_s(&hkdf_buf, sizeof(hkdf_buf), 0, sizeof(hkdf_buf));
}

sgx_status_t sgxsd_enclave_negotiate_request(const sgxsd_request_negotiation_request_t *p_request,
                                             sgxsd_request_negotiation_response_t *p_response) {
    if (!g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }

    // validate parameters
    if (p_request == NULL) {
	return SGX_ERROR_INVALID_PARAMETER;
    }
    if (p_response == NULL) {
	return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate ephemeral ecdh keypair
    sgxsd_curve25519_key_pair_t server_ephemeral_keypair;
    sgx_status_t generate_keypair_res = sgxsd_enclave_generate_curve25519_keypair(&server_ephemeral_keypair);
    if (generate_keypair_res != SGX_SUCCESS) {
        return generate_keypair_res;
    }

    // copy static ecdh keypair
    sgxsd_spin_lock(&g_sgxsd_enclave_dh_keypair_lock);
    sgxsd_curve25519_key_pair_t server_static_keypair = g_sgxsd_enclave_dh_keypair;
    sgxsd_spin_unlock(&g_sgxsd_enclave_dh_keypair_lock);

    // derive ephemeral ecdh shared secret
    sgxsd_curve25519_public_key_t ephemeral_dh_key;
    curve25519_donna(ephemeral_dh_key.x, server_ephemeral_keypair.privkey.x, p_request->client_pubkey.x);

    // erase ephemeral ecdh private key
    memset_s(&server_ephemeral_keypair.privkey, sizeof(server_ephemeral_keypair.privkey), 0, sizeof(server_ephemeral_keypair.privkey));

    // derive static ecdh shared secret
    sgxsd_curve25519_public_key_t static_dh_key;
    curve25519_donna(static_dh_key.x, server_static_keypair.privkey.x, p_request->client_pubkey.x);

    // erase static ecdh private key
    memset_s(&server_static_keypair.privkey, sizeof(server_static_keypair.privkey), 0, sizeof(server_static_keypair.privkey));

    // calculate HKDF salt = (client_ephemeral_pubkey || server_ephemeral_pubkey || server_static_pubkey)
    sgxsd_sha256_hash_t hkdf_salt;
    sgxsd_enclave_sha256(&hkdf_salt, 3, (sgxsd_sha256_buf_t[]) {
        { p_request->client_pubkey.x, sizeof(p_request->client_pubkey.x) },
        { server_ephemeral_keypair.pubkey.x, sizeof(server_ephemeral_keypair.pubkey.x) },
        { server_static_keypair.pubkey.x, sizeof(server_static_keypair.pubkey.x) },
    });

    // derive HKDF PRK (pseudo-random key) from salt and IKM = (ephemeral_dh_secret || static_dh_secret)
    sgxsd_pending_request_t pending_request;
    sgxsd_enclave_hmac_sha256(&pending_request.hkdf_prk, 3, (sgxsd_sha256_buf_t[]) {
        { hkdf_salt.data, sizeof(hkdf_salt.data) },
        { ephemeral_dh_key.x, sizeof(ephemeral_dh_key.x) },
        { static_dh_key.x, sizeof(static_dh_key.x) },
    });

    // erase ecdh shared secrets and HKDF salt
    memset_s(&ephemeral_dh_key, sizeof(ephemeral_dh_key), 0, sizeof(ephemeral_dh_key));
    memset_s(&static_dh_key, sizeof(static_dh_key), 0, sizeof(static_dh_key));
    memset_s(&hkdf_salt, sizeof(hkdf_salt), 0, sizeof(hkdf_salt));

    // set IV to 0 for the request id encryption in response
    memset_s(p_response->encrypted_pending_request_id.iv.data,
             sizeof(p_response->encrypted_pending_request_id.iv.data),
             0,
             sizeof(p_response->encrypted_pending_request_id.iv.data));

    // derive server sending AES-GCM key
    sgxsd_aes_gcm_key_t server_aes_gcm_key;
    sgxsd_enclave_derive_request_keys(&pending_request, NULL, &server_aes_gcm_key);

    // add pending request and have get its assigned ID
    sgxsd_pending_request_id_t pending_request_id;
    sgx_status_t add_pending_request_res =
        sgxsd_enclave_add_pending_request(&pending_request_id, &pending_request);
    if (add_pending_request_res != SGX_SUCCESS) {
        // erase server sending AES-GCM key
        memset_s(&server_aes_gcm_key, sizeof(server_aes_gcm_key), 0, sizeof(server_aes_gcm_key));
        return add_pending_request_res;
    }

    // erase HKDF PRK
    memset_s(&pending_request.hkdf_prk, sizeof(pending_request.hkdf_prk), 0, sizeof(pending_request.hkdf_prk));

    // encrypt pending request id
    _Static_assert(sizeof(pending_request_id) == sizeof(p_response->encrypted_pending_request_id.data), "sgxsd_request_negotiation_response_t.encrypted_pending_request_id.data overflow");
    sgx_status_t encrypt_pending_request_id_res =
        sgxsd_aes_gcm_encrypt(&server_aes_gcm_key, /* p_key */
                              &pending_request_id, sizeof(pending_request_id), /* p_src, src_len */
                              &p_response->encrypted_pending_request_id.data, /* p_dst */
                              &p_response->encrypted_pending_request_id.iv, /* p_iv */
                              NULL, 0, /* p_aad, aad_len */
                              &p_response->encrypted_pending_request_id.mac /* p_out_mac */);

    // erase server sending AES-GCM key
    memset_s(&server_aes_gcm_key, sizeof(server_aes_gcm_key), 0, sizeof(server_aes_gcm_key));

    if (encrypt_pending_request_id_res != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }

    // fill in rest of response fields
    p_response->server_static_pubkey = server_static_keypair.pubkey;
    p_response->server_ephemeral_pubkey = server_ephemeral_keypair.pubkey;

    return SGX_SUCCESS;
}

sgx_status_t sgxsd_enclave_server_reply_noerase(sgxsd_msg_buf_t reply_buf, const sgxsd_msg_from_t *p_from);
sgx_status_t sgxsd_enclave_server_reply(sgxsd_msg_buf_t reply_buf, sgxsd_msg_from_t *p_from) {
    sgx_status_t res = sgxsd_enclave_server_reply_noerase(reply_buf, p_from);
    if (reply_buf.data != NULL) {
        memset_s(reply_buf.data, reply_buf.size, 0, reply_buf.size);
    }
    if (p_from != NULL) {
        memset_s(p_from, sizeof(*p_from), 0, sizeof(*p_from));
    }
    return res;
}
sgx_status_t sgxsd_enclave_server_reply_noerase(sgxsd_msg_buf_t reply_buf, const sgxsd_msg_from_t *p_from) {
    if (p_from == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (!p_from->valid) {
        return SGX_ERROR_INVALID_STATE;
    }

    sgxsd_msg_header_t reply_header;
    if (reply_buf.data == NULL && reply_buf.size != 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // generate random IV for the reply message encryption
    sgx_status_t iv_rand_res = sgx_read_rand(reply_header.iv.data, sizeof(reply_header.iv.data));
    if (iv_rand_res != SGX_SUCCESS) {
        return iv_rand_res;
    }

    // set one bit of IV to 1 for the reply message encryption, to prevent collision with request negotiation response IV=0
    reply_header.iv.data[0] |= 1;

    // encrypt the reply message
    sgx_status_t encrypt_res =
        sgxsd_aes_gcm_encrypt(&p_from->server_key, /* p_key */
                              reply_buf.data, reply_buf.size, /* p_src, src_len */
                              reply_buf.data, /* p_dst */
                              &reply_header.iv, /* p_iv */
                              NULL, 0, /* p_aad, aad_len */
                              &reply_header.mac /* p_out_mac */);
    if (encrypt_res != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }

    // send encrypted reply to the untrusted code
    sgx_status_t reply_res;
    sgx_status_t reply_ocall_res =
        sgxsd_ocall_reply(&reply_res, &reply_header, reply_buf.data, reply_buf.size, p_from->tag);
    if (reply_ocall_res == SGX_SUCCESS) {
        return reply_res;
    } else {
        return reply_ocall_res;
    }
}

sgx_status_t sgxsd_enclave_server_noreply(sgxsd_msg_from_t *p_from) {
    if (p_from == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (!p_from->valid) {
        return SGX_ERROR_INVALID_STATE;
    }
    sgx_status_t reply_res;
    sgx_status_t reply_ocall_res =
        sgxsd_ocall_reply(&reply_res, NULL, NULL, 0, p_from->tag);
    memset_s(p_from, sizeof(*p_from), 0, sizeof(*p_from));
    if (reply_ocall_res == SGX_SUCCESS) {
        return reply_res;
    } else {
        return reply_ocall_res;
    }
}

sgx_status_t sgxsd_enclave_server_start_locked(const sgxsd_server_init_args_t *p_args, sgxsd_server_state_desc_t *p_state_desc);
sgx_status_t sgxsd_enclave_server_start(const sgxsd_server_init_args_t *p_args, sgxsd_server_state_handle_t state_handle) {
    if (!g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }
    if (state_handle >= g_sgxsd_enclave_max_servers) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgxsd_server_state_desc_t *p_state_desc = &g_sgxsd_enclave_server_states[state_handle];
    sgxsd_spin_lock(&p_state_desc->lock);

    sgx_status_t res = sgxsd_enclave_server_start_locked(p_args, p_state_desc);

    sgxsd_spin_unlock(&p_state_desc->lock);
    return res;
}
sgx_status_t sgxsd_enclave_server_start_locked(const sgxsd_server_init_args_t *p_args, sgxsd_server_state_desc_t *p_state_desc) {
    if (p_state_desc->valid) {
        return SGX_ERROR_INVALID_STATE;
    }
    sgx_status_t init_res = sgxsd_enclave_server_init(p_args, &p_state_desc->p_state);
    if (init_res == SGX_SUCCESS) {
        p_state_desc->valid = true;
        return SGX_SUCCESS;
    } else {
        return init_res;
    }
}

sgx_status_t sgxsd_enclave_server_call_locked(const sgxsd_server_handle_call_args_t *p_args,
                                              const sgxsd_msg_header_t *p_msg_header,
                                              uint8_t *msg_data, size_t msg_data_size,
                                              sgxsd_msg_tag_t msg_tag, sgxsd_server_state_desc_t *p_state_desc);
sgx_status_t sgxsd_enclave_server_call(const sgxsd_server_handle_call_args_t *p_args,
                                       const sgxsd_msg_header_t *p_msg_header,
                                       uint8_t *msg_data, size_t msg_data_size,
                                       sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle) {
    if (!g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }
    if (state_handle >= g_sgxsd_enclave_max_servers) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgxsd_server_state_desc_t *p_state_desc = &g_sgxsd_enclave_server_states[state_handle];
    sgxsd_spin_lock(&p_state_desc->lock);

    sgx_status_t res =
        sgxsd_enclave_server_call_locked(p_args, p_msg_header, msg_data, msg_data_size, msg_tag, p_state_desc);

    sgxsd_spin_unlock(&p_state_desc->lock);
    return res;
}
sgx_status_t sgxsd_enclave_server_call_locked(const sgxsd_server_handle_call_args_t *p_args,
                                              const sgxsd_msg_header_t *p_msg_header,
                                              uint8_t *msg_data, size_t msg_data_size,
                                              sgxsd_msg_tag_t msg_tag, sgxsd_server_state_desc_t *p_state_desc) {
    if (!p_state_desc->valid) {
        return SGX_ERROR_INVALID_STATE;
    }
    if (p_msg_header == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (msg_data == NULL || msg_data_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // get pending request by ID
    sgxsd_pending_request_t pending_request;
    sgx_status_t remove_pending_request_res = sgxsd_enclave_remove_pending_request(&p_msg_header->pending_request_id, &pending_request);
    if (remove_pending_request_res != SGX_SUCCESS) {
        return remove_pending_request_res;
    }

    // derive server and client sending AES-GCM keys
    sgxsd_aes_gcm_key_t client_key;
    sgxsd_msg_from_t msg_from = {
        .valid = true,
        .tag = msg_tag,
    };
    sgxsd_enclave_derive_request_keys(&pending_request, &client_key, &msg_from.server_key);

    // erase HKDF PRK
    memset_s(&pending_request, sizeof(pending_request), 0, sizeof(pending_request));

    // message is decrypted in-place
    sgxsd_msg_buf_t decrypted_msg = {
        .data = msg_data,
        .size = msg_data_size,
    };
    // validate and decrypt the message
    sgx_status_t decrypt_msg_res =
        sgxsd_aes_gcm_decrypt(&client_key, /* p_key */
                              msg_data, msg_data_size, /* p_src, src_len */
                              decrypted_msg.data, /* p_dst */
                              &p_msg_header->iv, /* p_iv */
                              &p_msg_header->pending_request_id, /* p_aad */
                              sizeof(p_msg_header->pending_request_id), /* aad_len */
                              &p_msg_header->mac /* p_in_mac */);

    // erase client sending AES-GCM key
    memset_s(&client_key, sizeof(client_key), 0, sizeof(client_key));

    if (decrypt_msg_res != SGX_SUCCESS) {
        // erase copy of plaintext ticket keys on stack
        memset_s(&msg_from, sizeof(msg_from), 0, sizeof(msg_from));
        if (decrypt_msg_res == SGX_ERROR_INVALID_PARAMETER) {
            return SGX_ERROR_UNEXPECTED;
        }
        return decrypt_msg_res;
    }

    // call the server_handle_call callback
    sgx_status_t server_call_res =
        sgxsd_enclave_server_handle_call(p_args, decrypted_msg, msg_from, &p_state_desc->p_state);

    // erase the decrypted message data
    memset_s(decrypted_msg.data, decrypted_msg.size, 0, decrypted_msg.size);

    // erase copy of plaintext ticket keys on stack
    memset_s(&msg_from, sizeof(msg_from), 0, sizeof(msg_from));

    return server_call_res;
}

sgx_status_t sgxsd_enclave_server_stop_locked(const sgxsd_server_terminate_args_t *p_args, sgxsd_server_state_desc_t *p_state_desc);
sgx_status_t sgxsd_enclave_server_stop(const sgxsd_server_terminate_args_t *p_args, sgxsd_server_state_handle_t state_handle) {
    if (!g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }
    if (state_handle >= g_sgxsd_enclave_max_servers) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgxsd_server_state_desc_t *p_state_desc = &g_sgxsd_enclave_server_states[state_handle];
    sgxsd_spin_lock(&p_state_desc->lock);

    sgx_status_t res = sgxsd_enclave_server_stop_locked(p_args, p_state_desc);

    sgxsd_spin_unlock(&p_state_desc->lock);
    return res;
}
sgx_status_t sgxsd_enclave_server_stop_locked(const sgxsd_server_terminate_args_t *p_args, sgxsd_server_state_desc_t *p_state_desc) {
    if (!p_state_desc->valid) {
        return SGX_ERROR_INVALID_STATE;
    }

    sgxsd_server_state_t *p_state = p_state_desc->p_state;
    // zero out old state to prevent replay / rewind
    memset_s(p_state_desc, sizeof(*p_state_desc), 0, sizeof(*p_state_desc));

    return sgxsd_enclave_server_terminate(p_args, p_state);
}

sgx_status_t sgxsd_enclave_ratelimit_fingerprint_locked(uint8_t fingerprint_key[32],
                                                        const sgxsd_server_handle_call_args_t *call_args,
                                                        const sgxsd_msg_header_t *msg_header,
                                                        uint8_t *msg_data, size_t msg_data_size,
                                                        sgxsd_msg_tag_t msg_tag,
                                                        sgxsd_server_state_desc_t *p_state_desc,
                                                        uint8_t *fingerprint, size_t fingerprint_size);

sgx_status_t sgxsd_enclave_ratelimit_fingerprint(uint8_t fingerprint_key[32],
                                                 const sgxsd_server_handle_call_args_t *call_args,
                                                 const sgxsd_msg_header_t *msg_header,
                                                 uint8_t *msg_data, size_t msg_data_size,
                                                 sgxsd_msg_tag_t msg_tag,
                                                 sgxsd_server_state_handle_t state_handle,
                                                 uint8_t *fingerprint, size_t fingerprint_size) {
    if (!g_sgxsd_enclave_node_initialized) {
        return SGX_ERROR_INVALID_STATE;
    }
    if (state_handle >= g_sgxsd_enclave_max_servers) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgxsd_server_state_desc_t *p_state_desc = &g_sgxsd_enclave_server_states[state_handle];
    sgxsd_spin_lock(&p_state_desc->lock);

    sgx_status_t res =
            sgxsd_enclave_ratelimit_fingerprint_locked(fingerprint_key, call_args, msg_header, msg_data, msg_data_size,
                                                       msg_tag, p_state_desc, fingerprint, fingerprint_size);

    sgxsd_spin_unlock(&p_state_desc->lock);
    return res;
}

sgx_status_t sgxsd_enclave_ratelimit_fingerprint_locked(uint8_t fingerprint_key[32],
                                                        const sgxsd_server_handle_call_args_t *call_args,
                                                        const sgxsd_msg_header_t *p_msg_header,
                                                        uint8_t *msg_data, size_t msg_data_size,
                                                        sgxsd_msg_tag_t msg_tag,
                                                        sgxsd_server_state_desc_t *p_state_desc,
                                                        uint8_t *fingerprint, size_t fingerprint_size) {
    if (!p_state_desc->valid) {
        return SGX_ERROR_INVALID_STATE;
    }
    if (p_msg_header == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (msg_data == NULL || msg_data_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // get pending request by ID
    sgxsd_pending_request_t pending_request;
    sgx_status_t get_pending_request_res = sgxsd_enclave_get_pending_request(&p_msg_header->pending_request_id, &pending_request);
    if (get_pending_request_res != SGX_SUCCESS) {
        return get_pending_request_res;
    }

    // derive server and client sending AES-GCM keys
    sgxsd_aes_gcm_key_t client_key;
    sgxsd_msg_from_t msg_from = {
            .valid = true,
            .tag = msg_tag,
    };
    sgxsd_enclave_derive_request_keys(&pending_request, &client_key, &msg_from.server_key);

    // erase HKDF PRK
    memset_s(&pending_request, sizeof(pending_request), 0, sizeof(pending_request));

    // message is decrypted in-place
    sgxsd_msg_buf_t decrypted_msg = {
            .data = msg_data,
            .size = msg_data_size,
    };
    // validate and decrypt the message
    sgx_status_t decrypt_msg_res =
            sgxsd_aes_gcm_decrypt(&client_key, /* p_key */
                                  msg_data, msg_data_size, /* p_src, src_len */
                                  decrypted_msg.data, /* p_dst */
                                  &p_msg_header->iv, /* p_iv */
                                  &p_msg_header->pending_request_id, /* p_aad */
                                  sizeof(p_msg_header->pending_request_id), /* aad_len */
                                  &p_msg_header->mac /* p_in_mac */);

    // erase client sending AES-GCM key
    memset_s(&client_key, sizeof(client_key), 0, sizeof(client_key));

    if (decrypt_msg_res != SGX_SUCCESS) {
        // erase copy of plaintext ticket keys on stack
        memset_s(&msg_from, sizeof(msg_from), 0, sizeof(msg_from));
        if (decrypt_msg_res == SGX_ERROR_INVALID_PARAMETER) {
            return SGX_ERROR_UNEXPECTED;
        }
        return decrypt_msg_res;
    }

    // call the server_handle_call callback
    sgx_status_t res =
            sgxsd_enclave_create_ratelimit_fingerprint(fingerprint_key, call_args, decrypted_msg, msg_from, fingerprint, fingerprint_size);

    // erase the decrypted message data
    memset_s(decrypted_msg.data, decrypted_msg.size, 0, decrypted_msg.size);

    // erase copy of plaintext ticket keys on stack
    memset_s(&msg_from, sizeof(msg_from), 0, sizeof(msg_from));

    return res;
}