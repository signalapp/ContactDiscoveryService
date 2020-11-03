#ifndef CDS_ENCLAVE_U_H__
#define CDS_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "cds.h"
#include "stdbool.h"
#include "stdint.h"
#include "sgx_quote.h"
#include "sgx_report.h"
#include "sgxsd.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SGXSD_OCALL_REPLY_DEFINED__
#define SGXSD_OCALL_REPLY_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, sgxsd_ocall_reply, (const sgxsd_msg_header_t* reply_header, const uint8_t* reply_data, size_t reply_data_size, sgxsd_msg_tag_t msg_tag));
#endif

sgx_status_t sgxsd_enclave_node_init(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_node_init_args_t* p_args);
sgx_status_t sgxsd_enclave_get_next_report(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_target_info_t qe_target_info, sgx_report_t* p_report);
sgx_status_t sgxsd_enclave_set_current_quote(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t sgxsd_enclave_negotiate_request(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_request_negotiation_request_t* p_request, sgxsd_request_negotiation_response_t* p_response);
sgx_status_t sgxsd_enclave_server_start(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_init_args_t* p_args, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_server_call(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_handle_call_args_t* p_args, const sgxsd_msg_header_t* msg_header, uint8_t* msg_data, size_t msg_size, sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_server_stop(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_terminate_args_t* p_args, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_ratelimit_fingerprint(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t fingerprint_key[32], const sgxsd_msg_header_t* msg_header, uint8_t* msg_data, size_t msg_data_size, sgxsd_msg_tag_t msg_tag, uint8_t* fingerprint, size_t fingerprint_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
