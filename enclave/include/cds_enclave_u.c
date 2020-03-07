#include "cds_enclave_u.h"
#include <errno.h>

typedef struct ms_sgxsd_enclave_node_init_t {
	sgx_status_t ms_retval;
	const sgxsd_node_init_args_t* ms_p_args;
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
	const sgxsd_request_negotiation_request_t* ms_p_request;
	sgxsd_request_negotiation_response_t* ms_p_response;
} ms_sgxsd_enclave_negotiate_request_t;

typedef struct ms_sgxsd_enclave_server_start_t {
	sgx_status_t ms_retval;
	const sgxsd_server_init_args_t* ms_p_args;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_start_t;

typedef struct ms_sgxsd_enclave_server_call_t {
	sgx_status_t ms_retval;
	const sgxsd_server_handle_call_args_t* ms_p_args;
	const sgxsd_msg_header_t* ms_msg_header;
	uint8_t* ms_msg_data;
	size_t ms_msg_size;
	sgxsd_msg_tag_t ms_msg_tag;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_call_t;

typedef struct ms_sgxsd_enclave_server_stop_t {
	sgx_status_t ms_retval;
	const sgxsd_server_terminate_args_t* ms_p_args;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_stop_t;

typedef struct ms_cds_enclave_update_ratelimit_state_t {
	sgx_status_t ms_retval;
	uuid_t ms_ratelimit_state_uuid;
	uint8_t* ms_ratelimit_state_data;
	size_t ms_ratelimit_state_size;
	phone_t* ms_query_phones;
	size_t ms_query_phone_count;
} ms_cds_enclave_update_ratelimit_state_t;

typedef struct ms_cds_enclave_delete_ratelimit_state_t {
	sgx_status_t ms_retval;
	uuid_t ms_ratelimit_state_uuid;
} ms_cds_enclave_delete_ratelimit_state_t;

typedef struct ms_sgxsd_ocall_reply_t {
	sgx_status_t ms_retval;
	const sgxsd_msg_header_t* ms_reply_header;
	const uint8_t* ms_reply_data;
	size_t ms_reply_data_size;
	sgxsd_msg_tag_t ms_msg_tag;
} ms_sgxsd_ocall_reply_t;

static sgx_status_t SGX_CDECL cds_enclave_sgxsd_ocall_reply(void* pms)
{
	ms_sgxsd_ocall_reply_t* ms = SGX_CAST(ms_sgxsd_ocall_reply_t*, pms);
	ms->ms_retval = sgxsd_ocall_reply(ms->ms_reply_header, ms->ms_reply_data, ms->ms_reply_data_size, ms->ms_msg_tag);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_cds_enclave = {
	1,
	{
		(void*)cds_enclave_sgxsd_ocall_reply,
	}
};
sgx_status_t sgxsd_enclave_node_init(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_node_init_args_t* p_args)
{
	sgx_status_t status;
	ms_sgxsd_enclave_node_init_t ms;
	ms.ms_p_args = p_args;
	status = sgx_ecall(eid, 0, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_get_next_report(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_target_info_t qe_target_info, sgx_report_t* p_report)
{
	sgx_status_t status;
	ms_sgxsd_enclave_get_next_report_t ms;
	ms.ms_qe_target_info = qe_target_info;
	ms.ms_p_report = p_report;
	status = sgx_ecall(eid, 1, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_set_current_quote(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sgxsd_enclave_set_current_quote_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_negotiate_request(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_request_negotiation_request_t* p_request, sgxsd_request_negotiation_response_t* p_response)
{
	sgx_status_t status;
	ms_sgxsd_enclave_negotiate_request_t ms;
	ms.ms_p_request = p_request;
	ms.ms_p_response = p_response;
	status = sgx_ecall(eid, 3, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_start(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_init_args_t* p_args, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_start_t ms;
	ms.ms_p_args = p_args;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 4, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_call(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_handle_call_args_t* p_args, const sgxsd_msg_header_t* msg_header, uint8_t* msg_data, size_t msg_size, sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_call_t ms;
	ms.ms_p_args = p_args;
	ms.ms_msg_header = msg_header;
	ms.ms_msg_data = msg_data;
	ms.ms_msg_size = msg_size;
	ms.ms_msg_tag = msg_tag;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 5, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_stop(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_terminate_args_t* p_args, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_stop_t ms;
	ms.ms_p_args = p_args;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 6, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t cds_enclave_update_ratelimit_state(sgx_enclave_id_t eid, sgx_status_t* retval, uuid_t ratelimit_state_uuid, uint8_t* ratelimit_state_data, size_t ratelimit_state_size, phone_t* query_phones, size_t query_phone_count)
{
	sgx_status_t status;
	ms_cds_enclave_update_ratelimit_state_t ms;
	ms.ms_ratelimit_state_uuid = ratelimit_state_uuid;
	ms.ms_ratelimit_state_data = ratelimit_state_data;
	ms.ms_ratelimit_state_size = ratelimit_state_size;
	ms.ms_query_phones = query_phones;
	ms.ms_query_phone_count = query_phone_count;
	status = sgx_ecall(eid, 7, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t cds_enclave_delete_ratelimit_state(sgx_enclave_id_t eid, sgx_status_t* retval, uuid_t ratelimit_state_uuid)
{
	sgx_status_t status;
	ms_cds_enclave_delete_ratelimit_state_t ms;
	ms.ms_ratelimit_state_uuid = ratelimit_state_uuid;
	status = sgx_ecall(eid, 8, &ocall_table_cds_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

