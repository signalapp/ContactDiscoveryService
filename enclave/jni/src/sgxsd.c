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
#include <stdarg.h>

#include "sgx_urts.h"
#include "sgx_uae_service.h"

#include "sabd_enclave_u.h"

// internal functions
typedef struct sgxsd_enclave_args {
    const char *path;
    bool debug;
    const sgx_launch_token_t *p_launch_token;
    const sgxsd_node_init_args_t *p_node_init_args;
} sgxsd_enclave_args_t;
static inline sgxsd_status_t sgxsd_init_get_epid(sgxsd_enclave_args_t enclave_args, sgxsd_start_callback_t p_callback, va_list callback_args);
static inline sgxsd_status_t sgxsd_init_create_enclave(sgxsd_enclave_args_t enclave_args, sgxsd_start_callback_t p_callback, va_list callback_args);
static inline sgxsd_status_t sgxsd_init_node_init(sgxsd_enclave_t enclave, sgxsd_enclave_args_t enclave_args, sgxsd_start_callback_t p_callback, va_list callback_args);

//
// public api
//

sgxsd_status_t sgxsd_start(const char *enclave_path, bool debug, const sgx_launch_token_t *p_launch_token, const sgxsd_node_init_args_t *p_node_init_args, sgxsd_start_callback_t p_callback, ...) {
    if (enclave_path == NULL || p_callback == NULL) {
        return sgxsd_status_error_code("badarg", SGX_ERROR_INVALID_PARAMETER);
    }

    va_list callback_args;
    va_start(callback_args, p_callback);

    sgxsd_enclave_args_t enclave_args = {
        .path = enclave_path,
        .debug = debug,
        .p_launch_token = p_launch_token,
        .p_node_init_args = p_node_init_args,
    };
    sgxsd_status_t rest_of_start_res = sgxsd_init_get_epid(enclave_args, p_callback, callback_args);

    va_end(callback_args);
    return rest_of_start_res;
}

static inline
sgxsd_status_t sgxsd_init_get_epid(sgxsd_enclave_args_t enclave_args, sgxsd_start_callback_t p_callback, va_list callback_args) {
    uint32_t epid;
    sgx_status_t sgx_get_epid_res = sgx_get_extended_epid_group_id(&epid);
    if (sgx_get_epid_res == SGX_SUCCESS) {
        if (epid == 0) {
            return sgxsd_init_create_enclave(enclave_args, p_callback, callback_args);
        } else {
            return sgxsd_status_error("bad_extended_epid_group_id");
        }
    } else {
        return sgxsd_status_error_code("sgx_get_extended_epid_group_id_fail", sgx_get_epid_res);
    }
}

static inline
sgxsd_status_t sgxsd_init_create_enclave(sgxsd_enclave_args_t enclave_args, sgxsd_start_callback_t p_callback, va_list callback_args) {
    sgxsd_enclave_t enclave = {
        .gid = { 0 },
        .launch_token = { 0 },
    };
    sgx_status_t init_quote_res = sgx_init_quote(&(sgx_target_info_t) {{{0}}}, &enclave.gid);
    if (init_quote_res == SGX_SUCCESS) {
        if (enclave_args.p_launch_token != NULL) {
            memcpy(enclave.launch_token, enclave_args.p_launch_token, sizeof(enclave.launch_token));
        }
        sgx_status_t create_enclave_res =
            sgx_create_enclave(enclave_args.path, enclave_args.debug, &enclave.launch_token, &(int){0}, &enclave.id, NULL);
        if (create_enclave_res == SGX_SUCCESS) {
            sgxsd_status_t rest_res = sgxsd_init_node_init(enclave, enclave_args, p_callback, callback_args);
            sgx_destroy_enclave(enclave.id);
            return rest_res;
        } else {
            return sgxsd_status_error_code("sgx_create_enclave_fail", create_enclave_res);
        }
    } else {
        return sgxsd_status_error_code("init_quote_fail", init_quote_res);
    }
}

static inline
sgxsd_status_t sgxsd_init_node_init(sgxsd_enclave_t enclave, sgxsd_enclave_args_t enclave_args, sgxsd_start_callback_t p_callback, va_list callback_args) {
    sgx_status_t node_init_res;
    sgx_status_t node_init_ecall_res =
        sgxsd_enclave_node_init(enclave.id, &node_init_res, enclave_args.p_node_init_args);
    if (node_init_ecall_res == SGX_SUCCESS) {
        if (node_init_res == SGX_SUCCESS) {
            return p_callback(enclave, callback_args);
        } else {
            return sgxsd_status_error_code("sgxsd_enclave_node_init_fail", node_init_res);
        }
    } else {
        return sgxsd_status_error_code("ecall_fail", node_init_ecall_res);
    }
}

sgxsd_status_t sgxsd_get_next_quote(sgx_enclave_id_t enclave_id, sgx_spid_t spid,
                                    const uint8_t *p_sig_rl, uint32_t sig_rl_size,
                                    sgx_quote_t *p_quote, uint32_t quote_size) {
  sgx_epid_group_id_t gid = {0};
  sgx_target_info_t qe_target_info = {{{0}}}; // NB: sgx_init_quote expects qe_target_info to be zeroed (undocumented!)
  sgx_status_t init_quote_res = sgx_init_quote(&qe_target_info, &gid);
  if (init_quote_res == SGX_SUCCESS) {
      sgx_report_t report;
      sgx_status_t get_next_report_res;
      sgx_status_t get_next_report_ecall_res =
        sgxsd_enclave_get_next_report(enclave_id, &get_next_report_res,
                                     qe_target_info, &report);
      if (get_next_report_ecall_res == SGX_SUCCESS) {
          if (get_next_report_res == SGX_SUCCESS) {
              sgx_status_t get_quote_res =
                  sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid,
                                NULL /* p_nonce */,
                                p_sig_rl, sig_rl_size,
                                NULL /* p_qe_report */,
                                p_quote, quote_size);
              if (get_quote_res == SGX_SUCCESS) {
                  return sgxsd_status_ok();
              } else {
                  return sgxsd_status_error_code("sgxsd_enclave_get_quote_fail", get_quote_res);
              }
          } else {
              return sgxsd_status_error_code("sgxsd_enclave_get_next_report_fail", get_next_report_res);
          }
      } else {
          return sgxsd_status_error_code("ecall_fail", get_next_report_ecall_res);
      }
  } else {
      return sgxsd_status_error_code("init_quote_fail", init_quote_res);
  }
}
