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
#include "sabd_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_sgxsd_enclave_node_init_t {
	sgx_status_t ms_retval;
	sgxsd_node_init_args_t* ms_p_args;
} ms_sgxsd_enclave_node_init_t;

typedef struct ms_sgxsd_enclave_get_next_quote_t {
	sgx_status_t ms_retval;
	sgx_target_info_t ms_qe_target_info;
	sgxsd_ra_get_quote_args_t* ms_p_get_quote_args;
	sgx_quote_t* ms_p_quote;
	uint32_t ms_quote_size;
} ms_sgxsd_enclave_get_next_quote_t;

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

typedef struct ms_sgxsd_ocall_ra_get_quote_t {
	sgx_status_t ms_retval;
	sgx_report_t ms_report;
	sgx_quote_nonce_t ms_nonce;
	sgxsd_ra_get_quote_args_t* ms_p_get_quote_args;
	sgx_report_t* ms_p_qe_report;
	sgx_quote_t* ms_p_quote;
	uint32_t ms_quote_size;
} ms_sgxsd_ocall_ra_get_quote_t;

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_node_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_node_init_t));
	ms_sgxsd_enclave_node_init_t* ms = SGX_CAST(ms_sgxsd_enclave_node_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgxsd_node_init_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(*_tmp_p_args);
	sgxsd_node_init_args_t* _in_p_args = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);

	if (_tmp_p_args != NULL) {
		_in_p_args = (sgxsd_node_init_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_args, _tmp_p_args, _len_p_args);
	}
	ms->ms_retval = sgxsd_enclave_node_init((const sgxsd_node_init_args_t*)_in_p_args);
err:
	if (_in_p_args) free((void*)_in_p_args);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_get_next_quote(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_get_next_quote_t));
	ms_sgxsd_enclave_get_next_quote_t* ms = SGX_CAST(ms_sgxsd_enclave_get_next_quote_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgxsd_ra_get_quote_args_t* _tmp_p_get_quote_args = ms->ms_p_get_quote_args;
	sgx_quote_t* _tmp_p_quote = ms->ms_p_quote;
	uint32_t _tmp_quote_size = ms->ms_quote_size;
	size_t _len_p_quote = _tmp_quote_size;
	sgx_quote_t* _in_p_quote = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_quote, _len_p_quote);

	if (_tmp_p_quote != NULL) {
		if ((_in_p_quote = (sgx_quote_t*)malloc(_len_p_quote)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_quote, 0, _len_p_quote);
	}
	ms->ms_retval = sgxsd_enclave_get_next_quote(ms->ms_qe_target_info, (const sgxsd_ra_get_quote_args_t*)_tmp_p_get_quote_args, _in_p_quote, _tmp_quote_size);
err:
	if (_in_p_quote) {
		memcpy(_tmp_p_quote, _in_p_quote, _len_p_quote);
		free(_in_p_quote);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_set_current_quote(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_set_current_quote_t));
	ms_sgxsd_enclave_set_current_quote_t* ms = SGX_CAST(ms_sgxsd_enclave_set_current_quote_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = sgxsd_enclave_set_current_quote();


	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_negotiate_request(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_negotiate_request_t));
	ms_sgxsd_enclave_negotiate_request_t* ms = SGX_CAST(ms_sgxsd_enclave_negotiate_request_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgxsd_request_negotiation_request_t* _tmp_p_request = ms->ms_p_request;
	size_t _len_p_request = sizeof(*_tmp_p_request);
	sgxsd_request_negotiation_request_t* _in_p_request = NULL;
	sgxsd_request_negotiation_response_t* _tmp_p_response = ms->ms_p_response;
	size_t _len_p_response = sizeof(*_tmp_p_response);
	sgxsd_request_negotiation_response_t* _in_p_response = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_request, _len_p_request);
	CHECK_UNIQUE_POINTER(_tmp_p_response, _len_p_response);

	if (_tmp_p_request != NULL) {
		_in_p_request = (sgxsd_request_negotiation_request_t*)malloc(_len_p_request);
		if (_in_p_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_request, _tmp_p_request, _len_p_request);
	}
	if (_tmp_p_response != NULL) {
		if ((_in_p_response = (sgxsd_request_negotiation_response_t*)malloc(_len_p_response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_response, 0, _len_p_response);
	}
	ms->ms_retval = sgxsd_enclave_negotiate_request((const sgxsd_request_negotiation_request_t*)_in_p_request, _in_p_response);
err:
	if (_in_p_request) free((void*)_in_p_request);
	if (_in_p_response) {
		memcpy(_tmp_p_response, _in_p_response, _len_p_response);
		free(_in_p_response);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_server_start(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_server_start_t));
	ms_sgxsd_enclave_server_start_t* ms = SGX_CAST(ms_sgxsd_enclave_server_start_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgxsd_server_init_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(*_tmp_p_args);
	sgxsd_server_init_args_t* _in_p_args = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);

	if (_tmp_p_args != NULL) {
		_in_p_args = (sgxsd_server_init_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_args, _tmp_p_args, _len_p_args);
	}
	ms->ms_retval = sgxsd_enclave_server_start((const sgxsd_server_init_args_t*)_in_p_args, ms->ms_state_handle);
err:
	if (_in_p_args) free((void*)_in_p_args);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_server_call(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_server_call_t));
	ms_sgxsd_enclave_server_call_t* ms = SGX_CAST(ms_sgxsd_enclave_server_call_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgxsd_server_handle_call_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(*_tmp_p_args);
	sgxsd_server_handle_call_args_t* _in_p_args = NULL;
	sgxsd_msg_header_t* _tmp_msg_header = ms->ms_msg_header;
	size_t _len_msg_header = sizeof(*_tmp_msg_header);
	sgxsd_msg_header_t* _in_msg_header = NULL;
	uint8_t* _tmp_msg_data = ms->ms_msg_data;
	size_t _tmp_msg_size = ms->ms_msg_size;
	size_t _len_msg_data = _tmp_msg_size;
	uint8_t* _in_msg_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);
	CHECK_UNIQUE_POINTER(_tmp_msg_header, _len_msg_header);
	CHECK_UNIQUE_POINTER(_tmp_msg_data, _len_msg_data);

	if (_tmp_p_args != NULL) {
		_in_p_args = (sgxsd_server_handle_call_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_args, _tmp_p_args, _len_p_args);
	}
	if (_tmp_msg_header != NULL) {
		_in_msg_header = (sgxsd_msg_header_t*)malloc(_len_msg_header);
		if (_in_msg_header == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_msg_header, _tmp_msg_header, _len_msg_header);
	}
	if (_tmp_msg_data != NULL) {
		_in_msg_data = (uint8_t*)malloc(_len_msg_data);
		if (_in_msg_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_msg_data, _tmp_msg_data, _len_msg_data);
	}
	ms->ms_retval = sgxsd_enclave_server_call((const sgxsd_server_handle_call_args_t*)_in_p_args, (const sgxsd_msg_header_t*)_in_msg_header, (const uint8_t*)_in_msg_data, _tmp_msg_size, ms->ms_msg_tag, ms->ms_state_handle);
err:
	if (_in_p_args) free((void*)_in_p_args);
	if (_in_msg_header) free((void*)_in_msg_header);
	if (_in_msg_data) free((void*)_in_msg_data);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgxsd_enclave_server_stop(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgxsd_enclave_server_stop_t));
	ms_sgxsd_enclave_server_stop_t* ms = SGX_CAST(ms_sgxsd_enclave_server_stop_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgxsd_server_terminate_args_t* _tmp_p_args = ms->ms_p_args;
	size_t _len_p_args = sizeof(*_tmp_p_args);
	sgxsd_server_terminate_args_t* _in_p_args = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_args, _len_p_args);

	if (_tmp_p_args != NULL) {
		_in_p_args = (sgxsd_server_terminate_args_t*)malloc(_len_p_args);
		if (_in_p_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_args, _tmp_p_args, _len_p_args);
	}
	ms->ms_retval = sgxsd_enclave_server_stop((const sgxsd_server_terminate_args_t*)_in_p_args, ms->ms_state_handle);
err:
	if (_in_p_args) free((void*)_in_p_args);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_sgxsd_enclave_node_init, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_get_next_quote, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_set_current_quote, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_negotiate_request, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_server_start, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_server_call, 0},
		{(void*)(uintptr_t)sgx_sgxsd_enclave_server_stop, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][7];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 1, 1, },
		{0, 1, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL sgxsd_ocall_reply(sgx_status_t* retval, const sgxsd_msg_header_t* reply_header, const uint8_t* reply_data, size_t reply_data_size, sgxsd_msg_tag_t msg_tag)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_reply_header = sizeof(*reply_header);
	size_t _len_reply_data = reply_data_size;

	ms_sgxsd_ocall_reply_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgxsd_ocall_reply_t);
	void *__tmp = NULL;

	ocalloc_size += (reply_header != NULL && sgx_is_within_enclave(reply_header, _len_reply_header)) ? _len_reply_header : 0;
	ocalloc_size += (reply_data != NULL && sgx_is_within_enclave(reply_data, _len_reply_data)) ? _len_reply_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgxsd_ocall_reply_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgxsd_ocall_reply_t));

	if (reply_header != NULL && sgx_is_within_enclave(reply_header, _len_reply_header)) {
		ms->ms_reply_header = (sgxsd_msg_header_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_reply_header);
		memcpy((void*)ms->ms_reply_header, reply_header, _len_reply_header);
	} else if (reply_header == NULL) {
		ms->ms_reply_header = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (reply_data != NULL && sgx_is_within_enclave(reply_data, _len_reply_data)) {
		ms->ms_reply_data = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_reply_data);
		memcpy((void*)ms->ms_reply_data, reply_data, _len_reply_data);
	} else if (reply_data == NULL) {
		ms->ms_reply_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_reply_data_size = reply_data_size;
	ms->ms_msg_tag = msg_tag;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgxsd_ocall_ra_get_quote(sgx_status_t* retval, sgx_report_t report, sgx_quote_nonce_t nonce, const sgxsd_ra_get_quote_args_t* p_get_quote_args, sgx_report_t* p_qe_report, sgx_quote_t* p_quote, uint32_t quote_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_qe_report = sizeof(*p_qe_report);
	size_t _len_p_quote = quote_size;

	ms_sgxsd_ocall_ra_get_quote_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgxsd_ocall_ra_get_quote_t);
	void *__tmp = NULL;

	ocalloc_size += (p_qe_report != NULL && sgx_is_within_enclave(p_qe_report, _len_p_qe_report)) ? _len_p_qe_report : 0;
	ocalloc_size += (p_quote != NULL && sgx_is_within_enclave(p_quote, _len_p_quote)) ? _len_p_quote : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgxsd_ocall_ra_get_quote_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgxsd_ocall_ra_get_quote_t));

	ms->ms_report = report;
	ms->ms_nonce = nonce;
	ms->ms_p_get_quote_args = SGX_CAST(sgxsd_ra_get_quote_args_t*, p_get_quote_args);
	if (p_qe_report != NULL && sgx_is_within_enclave(p_qe_report, _len_p_qe_report)) {
		ms->ms_p_qe_report = (sgx_report_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_p_qe_report);
		memset(ms->ms_p_qe_report, 0, _len_p_qe_report);
	} else if (p_qe_report == NULL) {
		ms->ms_p_qe_report = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (p_quote != NULL && sgx_is_within_enclave(p_quote, _len_p_quote)) {
		ms->ms_p_quote = (sgx_quote_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_p_quote);
		memset(ms->ms_p_quote, 0, _len_p_quote);
	} else if (p_quote == NULL) {
		ms->ms_p_quote = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_quote_size = quote_size;
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;
	if (p_qe_report) memcpy((void*)p_qe_report, ms->ms_p_qe_report, _len_p_qe_report);
	if (p_quote) memcpy((void*)p_quote, ms->ms_p_quote, _len_p_quote);

	sgx_ocfree();
	return status;
}

