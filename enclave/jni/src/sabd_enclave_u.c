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
#include "sabd_enclave_u.h"
#include <errno.h>

typedef struct ms_sgxsd_enclave_node_init_t {
	sgx_status_t ms_retval;
	sgxsd_node_init_args_t* ms_p_args;
} ms_sgxsd_enclave_node_init_t;

typedef struct ms_sgxsd_enclave_get_next_report_t {
	sgx_status_t ms_retval;
	sgx_target_info_t ms_qe_target_info;
	sgx_report_t* ms_p_report;
} ms_sgxsd_enclave_get_next_report_t;

typedef struct ms_sgxsd_enclave_set_current_quote_t {
	sgx_status_t ms_retval;
} ms_sgxsd_enclave_set_current_quote_t;

typedef struct ms_sgxsd_enclave_negotiate_request_t {
	sgx_status_t ms_retval;
	sgxsd_request_negotiation_request_t* ms_p_request;
	sgxsd_request_negotiation_response_t* ms_p_response;
} ms_sgxsd_enclave_negotiate_request_t;

typedef struct ms_sgxsd_enclave_server_start_t {
	sgx_status_t ms_retval;
	sgxsd_server_init_args_t* ms_p_args;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_start_t;

typedef struct ms_sgxsd_enclave_server_call_t {
	sgx_status_t ms_retval;
	sgxsd_server_handle_call_args_t* ms_p_args;
	sgxsd_msg_header_t* ms_msg_header;
	uint8_t* ms_msg_data;
	size_t ms_msg_size;
	sgxsd_msg_tag_t ms_msg_tag;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_call_t;

typedef struct ms_sgxsd_enclave_server_stop_t {
	sgx_status_t ms_retval;
	sgxsd_server_terminate_args_t* ms_p_args;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_stop_t;

typedef struct ms_sgxsd_ocall_reply_t {
	sgx_status_t ms_retval;
	sgxsd_msg_header_t* ms_reply_header;
	uint8_t* ms_reply_data;
	size_t ms_reply_data_size;
	sgxsd_msg_tag_t ms_msg_tag;
} ms_sgxsd_ocall_reply_t;

static sgx_status_t SGX_CDECL sabd_enclave_sgxsd_ocall_reply(void* pms)
{
	ms_sgxsd_ocall_reply_t* ms = SGX_CAST(ms_sgxsd_ocall_reply_t*, pms);
	ms->ms_retval = sgxsd_ocall_reply((const sgxsd_msg_header_t*)ms->ms_reply_header, (const uint8_t*)ms->ms_reply_data, ms->ms_reply_data_size, ms->ms_msg_tag);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_sabd_enclave = {
	1,
	{
		(void*)sabd_enclave_sgxsd_ocall_reply,
	}
};
sgx_status_t sgxsd_enclave_node_init(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_node_init_args_t* p_args)
{
	sgx_status_t status;
	ms_sgxsd_enclave_node_init_t ms;
	ms.ms_p_args = (sgxsd_node_init_args_t*)p_args;
	status = sgx_ecall(eid, 0, &ocall_table_sabd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_get_next_report(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_target_info_t qe_target_info, sgx_report_t* p_report)
{
	sgx_status_t status;
	ms_sgxsd_enclave_get_next_report_t ms;
	ms.ms_qe_target_info = qe_target_info;
	ms.ms_p_report = p_report;
	status = sgx_ecall(eid, 1, &ocall_table_sabd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_set_current_quote(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sgxsd_enclave_set_current_quote_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_sabd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_negotiate_request(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_request_negotiation_request_t* p_request, sgxsd_request_negotiation_response_t* p_response)
{
	sgx_status_t status;
	ms_sgxsd_enclave_negotiate_request_t ms;
	ms.ms_p_request = (sgxsd_request_negotiation_request_t*)p_request;
	ms.ms_p_response = p_response;
	status = sgx_ecall(eid, 3, &ocall_table_sabd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_start(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_init_args_t* p_args, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_start_t ms;
	ms.ms_p_args = (sgxsd_server_init_args_t*)p_args;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 4, &ocall_table_sabd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_call(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_handle_call_args_t* p_args, const sgxsd_msg_header_t* msg_header, const uint8_t* msg_data, size_t msg_size, sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_call_t ms;
	ms.ms_p_args = (sgxsd_server_handle_call_args_t*)p_args;
	ms.ms_msg_header = (sgxsd_msg_header_t*)msg_header;
	ms.ms_msg_data = (uint8_t*)msg_data;
	ms.ms_msg_size = msg_size;
	ms.ms_msg_tag = msg_tag;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 5, &ocall_table_sabd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_stop(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_terminate_args_t* p_args, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_stop_t ms;
	ms.ms_p_args = (sgxsd_server_terminate_args_t*)p_args;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 6, &ocall_table_sabd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

