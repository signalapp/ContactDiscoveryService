#include "cds_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_node_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_node_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgxsd_enclave_node_init_t* ms = SGX_CAST(ms_sgxsd_enclave_node_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgxsd_node_init_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(sgxsd_node_init_args_t);
	sgxsd_node_init_args_t* _in_p_args = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_args != NULL && _len_p_args != 0) {
		_in_p_args = (sgxsd_node_init_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_args, _len_p_args, _tmp_p_args, _len_p_args)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgxsd_enclave_node_init((const sgxsd_node_init_args_t*)_in_p_args);

err:
	if (_in_p_args) free(_in_p_args);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_get_next_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_get_next_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgxsd_enclave_get_next_report_t* ms = SGX_CAST(ms_sgxsd_enclave_get_next_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}

	ms->ms_retval = sgxsd_enclave_get_next_report(ms->ms_qe_target_info, _in_p_report);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_report) free(_in_p_report);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_set_current_quote(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_set_current_quote_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgxsd_enclave_set_current_quote_t* ms = SGX_CAST(ms_sgxsd_enclave_set_current_quote_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = sgxsd_enclave_set_current_quote();


	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_negotiate_request(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_negotiate_request_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgxsd_enclave_negotiate_request_t* ms = SGX_CAST(ms_sgxsd_enclave_negotiate_request_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgxsd_request_negotiation_request_t* _tmp_p_request = ms->ms_p_request;
	size_t _len_p_request = sizeof(sgxsd_request_negotiation_request_t);
	sgxsd_request_negotiation_request_t* _in_p_request = NULL;
	sgxsd_request_negotiation_response_t* _tmp_p_response = ms->ms_p_response;
	size_t _len_p_response = sizeof(sgxsd_request_negotiation_response_t);
	sgxsd_request_negotiation_response_t* _in_p_response = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_request, _len_p_request);
	CHECK_UNIQUE_POINTER(_tmp_p_response, _len_p_response);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_request != NULL && _len_p_request != 0) {
		_in_p_request = (sgxsd_request_negotiation_request_t*)malloc(_len_p_request);
		if (_in_p_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_request, _len_p_request, _tmp_p_request, _len_p_request)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_response != NULL && _len_p_response != 0) {
		if ((_in_p_response = (sgxsd_request_negotiation_response_t*)malloc(_len_p_response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_response, 0, _len_p_response);
	}

	ms->ms_retval = sgxsd_enclave_negotiate_request((const sgxsd_request_negotiation_request_t*)_in_p_request, _in_p_response);
	if (_in_p_response) {
		if (memcpy_s(_tmp_p_response, _len_p_response, _in_p_response, _len_p_response)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_request) free(_in_p_request);
	if (_in_p_response) free(_in_p_response);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_server_start(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_server_start_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgxsd_enclave_server_start_t* ms = SGX_CAST(ms_sgxsd_enclave_server_start_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgxsd_server_init_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(sgxsd_server_init_args_t);
	sgxsd_server_init_args_t* _in_p_args = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_args != NULL && _len_p_args != 0) {
		_in_p_args = (sgxsd_server_init_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_args, _len_p_args, _tmp_p_args, _len_p_args)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgxsd_enclave_server_start((const sgxsd_server_init_args_t*)_in_p_args, ms->ms_state_handle);

err:
	if (_in_p_args) free(_in_p_args);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_server_call(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_server_call_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgxsd_enclave_server_call_t* ms = SGX_CAST(ms_sgxsd_enclave_server_call_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgxsd_server_handle_call_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(sgxsd_server_handle_call_args_t);
	sgxsd_server_handle_call_args_t* _in_p_args = NULL;
	const sgxsd_msg_header_t* _tmp_msg_header = ms->ms_msg_header;
	size_t _len_msg_header = sizeof(sgxsd_msg_header_t);
	sgxsd_msg_header_t* _in_msg_header = NULL;
	uint8_t* _tmp_msg_data = ms->ms_msg_data;
	size_t _tmp_msg_size = ms->ms_msg_size;
	size_t _len_msg_data = _tmp_msg_size;
	uint8_t* _in_msg_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);
	CHECK_UNIQUE_POINTER(_tmp_msg_header, _len_msg_header);
	CHECK_UNIQUE_POINTER(_tmp_msg_data, _len_msg_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_args != NULL && _len_p_args != 0) {
		_in_p_args = (sgxsd_server_handle_call_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_args, _len_p_args, _tmp_p_args, _len_p_args)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg_header != NULL && _len_msg_header != 0) {
		_in_msg_header = (sgxsd_msg_header_t*)malloc(_len_msg_header);
		if (_in_msg_header == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg_header, _len_msg_header, _tmp_msg_header, _len_msg_header)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg_data != NULL && _len_msg_data != 0) {
		if ( _len_msg_data % sizeof(*_tmp_msg_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_msg_data = (uint8_t*)malloc(_len_msg_data);
		if (_in_msg_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg_data, _len_msg_data, _tmp_msg_data, _len_msg_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgxsd_enclave_server_call((const sgxsd_server_handle_call_args_t*)_in_p_args, (const sgxsd_msg_header_t*)_in_msg_header, _in_msg_data, _tmp_msg_size, ms->ms_msg_tag, ms->ms_state_handle);

err:
	if (_in_p_args) free(_in_p_args);
	if (_in_msg_header) free(_in_msg_header);
	if (_in_msg_data) free(_in_msg_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_server_stop(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_server_stop_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgxsd_enclave_server_stop_t* ms = SGX_CAST(ms_sgxsd_enclave_server_stop_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgxsd_server_terminate_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(sgxsd_server_terminate_args_t);
	sgxsd_server_terminate_args_t* _in_p_args = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_args != NULL && _len_p_args != 0) {
		_in_p_args = (sgxsd_server_terminate_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_args, _len_p_args, _tmp_p_args, _len_p_args)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgxsd_enclave_server_stop((const sgxsd_server_terminate_args_t*)_in_p_args, ms->ms_state_handle);

err:
	if (_in_p_args) free(_in_p_args);
	return status;
}

static sgx_status_t SGX_CDECL sgx_cds_enclave_update_ratelimit_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_cds_enclave_update_ratelimit_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_cds_enclave_update_ratelimit_state_t* ms = SGX_CAST(ms_cds_enclave_update_ratelimit_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_ratelimit_state_data = ms->ms_ratelimit_state_data;
	size_t _tmp_ratelimit_state_size = ms->ms_ratelimit_state_size;
	size_t _len_ratelimit_state_data = _tmp_ratelimit_state_size;
	uint8_t* _in_ratelimit_state_data = NULL;
	phone_t* _tmp_query_phones = ms->ms_query_phones;
	size_t _tmp_query_phone_count = ms->ms_query_phone_count;
	size_t _len_query_phones = _tmp_query_phone_count * sizeof(phone_t);
	phone_t* _in_query_phones = NULL;

	if (sizeof(*_tmp_query_phones) != 0 &&
		(size_t)_tmp_query_phone_count > (SIZE_MAX / sizeof(*_tmp_query_phones))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_ratelimit_state_data, _len_ratelimit_state_data);
	CHECK_UNIQUE_POINTER(_tmp_query_phones, _len_query_phones);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ratelimit_state_data != NULL && _len_ratelimit_state_data != 0) {
		if ( _len_ratelimit_state_data % sizeof(*_tmp_ratelimit_state_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ratelimit_state_data = (uint8_t*)malloc(_len_ratelimit_state_data);
		if (_in_ratelimit_state_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ratelimit_state_data, _len_ratelimit_state_data, _tmp_ratelimit_state_data, _len_ratelimit_state_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_query_phones != NULL && _len_query_phones != 0) {
		_in_query_phones = (phone_t*)malloc(_len_query_phones);
		if (_in_query_phones == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_query_phones, _len_query_phones, _tmp_query_phones, _len_query_phones)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = cds_enclave_update_ratelimit_state(ms->ms_ratelimit_state_uuid, _in_ratelimit_state_data, _tmp_ratelimit_state_size, _in_query_phones, _tmp_query_phone_count);

err:
	if (_in_ratelimit_state_data) free(_in_ratelimit_state_data);
	if (_in_query_phones) free(_in_query_phones);
	return status;
}

static sgx_status_t SGX_CDECL sgx_cds_enclave_delete_ratelimit_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_cds_enclave_delete_ratelimit_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_cds_enclave_delete_ratelimit_state_t* ms = SGX_CAST(ms_cds_enclave_delete_ratelimit_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = cds_enclave_delete_ratelimit_state(ms->ms_ratelimit_state_uuid);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[9];
} g_ecall_table = {
	9,
	{
		{(void*)(uintptr_t)sgx_sgxsd_enclave_node_init, 0, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_get_next_report, 0, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_set_current_quote, 0, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_negotiate_request, 0, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_server_start, 0, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_server_call, 0, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_server_stop, 0, 0},
		{(void*)(uintptr_t)sgx_cds_enclave_update_ratelimit_state, 0, 0},
		{(void*)(uintptr_t)sgx_cds_enclave_delete_ratelimit_state, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][9];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL sgxsd_ocall_reply(sgx_status_t* retval, const sgxsd_msg_header_t* reply_header, const uint8_t* reply_data, size_t reply_data_size, sgxsd_msg_tag_t msg_tag)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_reply_header = sizeof(sgxsd_msg_header_t);
	size_t _len_reply_data = reply_data_size;

	ms_sgxsd_ocall_reply_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgxsd_ocall_reply_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(reply_header, _len_reply_header);
	CHECK_ENCLAVE_POINTER(reply_data, _len_reply_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (reply_header != NULL) ? _len_reply_header : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (reply_data != NULL) ? _len_reply_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgxsd_ocall_reply_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgxsd_ocall_reply_t));
	ocalloc_size -= sizeof(ms_sgxsd_ocall_reply_t);

	if (reply_header != NULL) {
		ms->ms_reply_header = (const sgxsd_msg_header_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, reply_header, _len_reply_header)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_reply_header);
		ocalloc_size -= _len_reply_header;
	} else {
		ms->ms_reply_header = NULL;
	}
	
	if (reply_data != NULL) {
		ms->ms_reply_data = (const uint8_t*)__tmp;
		if (_len_reply_data % sizeof(*reply_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, reply_data, _len_reply_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_reply_data);
		ocalloc_size -= _len_reply_data;
	} else {
		ms->ms_reply_data = NULL;
	}
	
	ms->ms_reply_data_size = reply_data_size;
	ms->ms_msg_tag = msg_tag;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

