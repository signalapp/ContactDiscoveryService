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
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <jni.h>

#include "sgx_uae_service.h"

#include "sgxsd.h"
#include "sabd.h"
#include "sabd_enclave_u.h"

//
// configurables
//

#define SGXSD_JNI_PACKAGE_STR "org/whispersystems/contactdiscovery/enclave/"
#define SGXSD_JNI_CLASS_STR SGXSD_JNI_PACKAGE_STR "SgxEnclave"
#define SGXSD_JNI_CLASS_METHOD(Name) Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_ ## Name

//
// thread locals
//

_Thread_local static JNIEnv *g_sgxsd_thread_jni_env;

//
// exception handling
//

bool sgxsd_jni_throw_exception_v(JNIEnv *env, jclass ex_class, char *ex_init_sig, va_list args) {
    jmethodID method_id = (*env)->GetMethodID(env, ex_class, "<init>", ex_init_sig);
    if (method_id != NULL) {
        jthrowable ex = (*env)->NewObjectV(env, ex_class, method_id, args);
        if (ex != NULL) {
            jint throw_res = (*env)->Throw(env, ex);
            
            (*env)->DeleteLocalRef(env, ex);
            return throw_res == 0;
        } else {
            return false;
        }
    } else {
        return false;
    }
}
bool sgxsd_jni_throw_exception(JNIEnv *env, char *ex_class_name, char *ex_init_sig, ...) {
    jclass ex_class = (*env)->FindClass(env, ex_class_name);
    if (ex_class != NULL) {
        va_list args;
        va_start(args, ex_init_sig);
        bool throw_res = sgxsd_jni_throw_exception_v(env, ex_class, ex_init_sig, args);
        va_end(args);

        (*env)->DeleteLocalRef(env, ex_class);
        return throw_res;
    } else {
        return false;
    }
}

bool sgxsd_jni_throw_sgxsd_exception(JNIEnv *env, const char *name_arg, int64_t code_arg) {
    if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
        const char *name = name_arg != NULL? name_arg : "";
        jstring name_str = (*env)->NewStringUTF(env, name);
        if (name_str != NULL) {
            bool throw_res = sgxsd_jni_throw_exception(env, SGXSD_JNI_PACKAGE_STR "SgxException",
                                                       "(Ljava/lang/String;J)V", name_str, code_arg);
            (*env)->DeleteLocalRef(env, name_str);
            return throw_res;
        } else {
            return false;
        }
    } else {
        return false;
    }
}
bool sgxsd_jni_status_maybe_throw_sgxsd_exception(JNIEnv *env, sgxsd_status_t status) {
    if (!status.ok) {
        return sgxsd_jni_throw_sgxsd_exception(env, status.name, status.code);
    } else {
        return false;
    }
}

//
// utils
//

char *sgxsd_jni_copy_jstring(JNIEnv *env, jstring str) {
    if (str != NULL) {
        const char *str_chars = (*env)->GetStringUTFChars(env, str, NULL);
        if (str_chars != NULL) {
            char *chars_copy = strdup(str_chars);
            (*env)->ReleaseStringUTFChars(env, str, str_chars);
            return chars_copy;
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "get_string_utf_fail", 0);
            return NULL;
        }
    } else {
        return NULL;
    }
}

jbyteArray sgxsd_jni_to_byte_array(JNIEnv *env, const void *data, jsize data_size) {
    jbyteArray new_byte_array = (*env)->NewByteArray(env, data_size);
    if (new_byte_array != NULL) {
        (*env)->SetByteArrayRegion(env, new_byte_array, 0, data_size, data);
        if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
            return new_byte_array;
        } else {
            (*env)->DeleteLocalRef(env, new_byte_array);
            return NULL;
        }
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "new_byte_array_fail", 0);
        return NULL;
    }
}

void *sgxsd_jni_copy_byte_array(JNIEnv *env, jbyteArray j_byte_array, size_t *p_size) {
    if (j_byte_array != NULL) {
        jsize j_byte_array_size = (*env)->GetArrayLength(env, j_byte_array);
        size_t byte_array_size = (size_t) j_byte_array_size;
        if (j_byte_array_size > 0) {
            *p_size = byte_array_size;
            uint8_t *byte_array = malloc(byte_array_size);
            if (byte_array != NULL) {
                (*env)->GetByteArrayRegion(env, j_byte_array, 0, j_byte_array_size, (jbyte *) byte_array);
                (*env)->DeleteLocalRef(env, j_byte_array);

                if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
                    return byte_array;
                } else {
                    // an exception occurred
                    free(byte_array);
                    return NULL;
                }
            } else {
                sgxsd_jni_throw_sgxsd_exception(env, "malloc_fail", errno);
                return NULL;
            }
        } else {
            *p_size = 0;
            return NULL;
        }
    } else {
        *p_size = 0;
        return NULL;
    }
}

jobject sgxsd_jni_new_object_v(JNIEnv *env, jclass class, const char *init_sig, va_list args) {
    jmethodID init_method_id =
        (*env)->GetMethodID(env, class, "<init>", init_sig);
    if (init_method_id != NULL) {
        jobject new_obj = (*env)->NewObjectV(env, class, init_method_id, args);
        if (new_obj != NULL) {
            return new_obj;
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "new_object_fail", 0);
            return NULL;
        }
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "get_init_method_id_fail", 0);
        return NULL;
    }
}
jobject sgxsd_jni_new_object_by_name(JNIEnv *env, const char *class_name, const char *init_sig, ...) {
    jclass class = (*env)->FindClass(env, class_name);
    if (class != NULL) {
        va_list args;
        va_start(args, init_sig);

        jobject new_object_res = sgxsd_jni_new_object_v(env, class, init_sig, args);

        (*env)->DeleteLocalRef(env, class);
        va_end(args);
        return new_object_res;
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "find_class_fail", 0);
        return NULL;
    }
}

//
// sgxsd_start callback
//

sgxsd_status_t sgxsd_jni_start_callback(sgxsd_enclave_t enclave, JNIEnv *env, jobject j_callback_obj);

// macro to type-check arguments to sgxsd_start
#define sgxsd_jni_start_callback_args(Env, Callback) \
    sgxsd_jni_start_callback_v,                      \
        _Generic((Env), JNIEnv *: Env),              \
        _Generic((Callback), jobject: Callback)
sgxsd_status_t sgxsd_jni_start_callback_v(sgxsd_enclave_t enclave, va_list args) {
    JNIEnv *env = va_arg(args, JNIEnv *);
    jobject j_callback_obj = va_arg(args, jobject);
    return sgxsd_jni_start_callback(enclave, env, j_callback_obj);
}

//
// ocalls
//

typedef struct sgxsd_jni_msg_tag {
    jobject j_callback_ref;
    jmethodID j_callback_method_id;
} sgxsd_jni_msg_tag_t;

sgx_status_t sgxsd_ocall_reply(const sgxsd_msg_header_t *p_reply_header,
                               const uint8_t *reply_data, size_t reply_data_size,
                               sgxsd_msg_tag_t msg_tag) {
    JNIEnv *env = g_sgxsd_thread_jni_env;
    sgxsd_jni_msg_tag_t jni_msg_tag = *(sgxsd_jni_msg_tag_t *) msg_tag.p_tag;
    free(msg_tag.p_tag);

    jsize j_reply_size = (jsize) reply_data_size;
    jbyteArray j_reply_data = sgxsd_jni_to_byte_array(env, reply_data, j_reply_size);
    jbyteArray j_reply_iv = sgxsd_jni_to_byte_array(env, p_reply_header->iv.data, sizeof(p_reply_header->iv.data));
    jbyteArray j_reply_mac = sgxsd_jni_to_byte_array(env, p_reply_header->mac.data, sizeof(p_reply_header->mac.data));

    jobject j_callback_obj = (*env)->NewLocalRef(env, jni_msg_tag.j_callback_ref);
    (*env)->DeleteGlobalRef(env, jni_msg_tag.j_callback_ref);
    if (j_callback_obj != NULL) {
        // do the null/error checking and throwing an exception in the java callback
        (*env)->CallVoidMethod(env, j_callback_obj, jni_msg_tag.j_callback_method_id,
                               j_reply_data, j_reply_iv, j_reply_mac);
        (*env)->DeleteLocalRef(env, j_callback_obj);
    }
    return SGX_SUCCESS;
}

//
// JNI entrypoints
//

JNIEXPORT void JNICALL SGXSD_JNI_CLASS_METHOD(nativeEnclaveStart)
    (JNIEnv *env, jclass class, jstring j_enclave_path, jboolean j_debug, jbyteArray j_launch_token,
     jbyte j_pending_requests_table_order, jobject j_callback_obj) {
    if (j_callback_obj == NULL) {
        sgxsd_jni_throw_exception(env, "java/lang/NullPointerException", "()V");
        return;
    }

    char *enclave_path = sgxsd_jni_copy_jstring(env, j_enclave_path);
    if (enclave_path != NULL) {
        sgx_launch_token_t valid_launch_token;
        sgx_launch_token_t *p_launch_token;
        if (j_launch_token != NULL) {
            p_launch_token = &valid_launch_token;
            (*env)->GetByteArrayRegion(env, j_launch_token, 0, sizeof(valid_launch_token),
                                       (jbyte *) &valid_launch_token);
        } else {
            p_launch_token = NULL;
        }
        sgxsd_node_init_args_t node_init_args = {
            .pending_requests_table_order = j_pending_requests_table_order,
        };
        if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
            sgxsd_status_t start_res = sgxsd_start(enclave_path, j_debug == JNI_TRUE, p_launch_token, &node_init_args,
                                                   sgxsd_jni_start_callback_args(env, j_callback_obj));

            free(enclave_path);

            sgxsd_jni_status_maybe_throw_sgxsd_exception(env, start_res);
            return;
        } else {
            // an exception occurred
            free(enclave_path);
            return;
        }
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "copy_jstring_fail", 0);
        return;
    }
}
sgxsd_status_t sgxsd_jni_start_callback(sgxsd_enclave_t enclave, JNIEnv *env, jobject j_callback_obj) {

    jclass class = (*env)->GetObjectClass(env, j_callback_obj);
    if (class != NULL) {
        jmethodID callback_method_id = (*env)->GetMethodID(env, class, "runEnclave", "(JJ[B)V");
        if (callback_method_id != NULL) {
            jlong j_enclave_id = enclave.id;
            jlong j_gid = enclave.gid32;
            // an exception might be thrown, which will be handled by the JVM in CallVoidMethod
            jbyteArray j_launch_token = sgxsd_jni_to_byte_array(env, enclave.launch_token, sizeof(enclave.launch_token));
            (*env)->CallVoidMethod(env, j_callback_obj, callback_method_id, j_enclave_id, j_gid, j_launch_token);
            return sgxsd_status_ok();
        } else {
            return sgxsd_status_error("get_start_callback_method_id_fail");
        }
    } else {
        return sgxsd_status_error("find_start_callback_class_fail");
    }
}

static inline
jobject sgxsd_jni_get_next_quote(JNIEnv *env, sgx_enclave_id_t enclave_id, sgx_spid_t spid,
                                 uint8_t *sig_rl, uint32_t sig_rl_size) {
    uint32_t quote_size;
    sgx_status_t quote_size_res = sgx_calc_quote_size(sig_rl, sig_rl_size, &quote_size);
    if (quote_size_res == SGX_SUCCESS) {
        sgx_quote_t *p_quote = malloc(quote_size);
        if (p_quote != NULL) {
            sgxsd_status_t get_next_quote_res =
                sgxsd_get_next_quote(enclave_id, spid, sig_rl, sig_rl_size, p_quote, quote_size);

            jobject j_quote;
            if (get_next_quote_res.ok) {
                // do the null checking and throwing an exception in the java constructor
                j_quote = sgxsd_jni_to_byte_array(env, p_quote, quote_size);
            } else {
                j_quote = NULL;
            }

            free(p_quote);
            sgxsd_jni_status_maybe_throw_sgxsd_exception(env, get_next_quote_res);
            return j_quote;
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "malloc_fail", errno);
            return NULL;
        }
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "quote_size_fail", quote_size_res);
        return NULL;
    }
}

JNIEXPORT jobject JNICALL SGXSD_JNI_CLASS_METHOD(nativeGetNextQuote)
    (JNIEnv *env, jobject class, jlong j_enclave_id, jbyteArray j_spid, jbyteArray j_sig_rl) {
    if (j_spid == NULL) {
        sgxsd_jni_throw_exception(env, "java/lang/NullPointerException", "()V");
        return NULL;
    }
    sgx_enclave_id_t enclave_id = j_enclave_id;
    sgx_spid_t spid;

    (*env)->GetByteArrayRegion(env, j_spid, 0, sizeof(spid.id), (jbyte *) &spid.id);

    if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
        size_t sig_rl_size;
        uint8_t *sig_rl = sgxsd_jni_copy_byte_array(env, j_sig_rl, &sig_rl_size);
        if (sig_rl != NULL || sig_rl_size == 0) {
            jobject get_next_quote_res = sgxsd_jni_get_next_quote(env, enclave_id, spid, sig_rl, sig_rl_size);
            free(sig_rl);
            return get_next_quote_res;
        } else {
            // an exception occurred
            return NULL;
        }
    } else {
        // an exception occurred
        return NULL;
    }
}

JNIEXPORT void JNICALL SGXSD_JNI_CLASS_METHOD(nativeSetCurrentQuote)
    (JNIEnv *env, jobject class, jlong j_enclave_id) {
    sgx_enclave_id_t enclave_id = j_enclave_id;

    sgx_status_t set_current_quote_res;
    sgx_status_t set_current_quote_ecall_res = sgxsd_enclave_set_current_quote(enclave_id, &set_current_quote_res);
    if (set_current_quote_ecall_res == SGX_SUCCESS) {
        if (set_current_quote_res == SGX_SUCCESS) {
            return;
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "set_current_quote_fail", set_current_quote_res);
            return;
        }
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "ecall_fail", set_current_quote_ecall_res);
        return;
    }        
}

JNIEXPORT jobject JNICALL SGXSD_JNI_CLASS_METHOD(nativeNegotiateRequest)
    (JNIEnv *env, jobject class, jlong j_enclave_id, jbyteArray j_client_pubkey) {
    if (j_client_pubkey == NULL) {
        sgxsd_jni_throw_exception(env, "java/lang/NullPointerException", "()V");
        return NULL;
    }

    sgx_enclave_id_t enclave_id = j_enclave_id;

    sgxsd_request_negotiation_request_t request;
    (*env)->GetByteArrayRegion(env, j_client_pubkey, 0, sizeof(request.client_pubkey.x), (jbyte *) &request.client_pubkey.x[0]);

    if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
        sgxsd_request_negotiation_response_t response;
        sgx_status_t negotiate_request_res;
        sgx_status_t negotiate_request_ecall_res =
            sgxsd_enclave_negotiate_request(enclave_id, &negotiate_request_res, &request, &response);
        if (negotiate_request_ecall_res == SGX_SUCCESS) {
            if (negotiate_request_res == SGX_SUCCESS) {
                // local refs to these new arrays will be dropped after we return
                jbyteArray j_server_static_pubkey = sgxsd_jni_to_byte_array(env, response.server_static_pubkey.x, sizeof(response.server_static_pubkey.x));
                jbyteArray j_server_ephemeral_pubkey = sgxsd_jni_to_byte_array(env, response.server_ephemeral_pubkey.x, sizeof(response.server_ephemeral_pubkey.x));
                jbyteArray j_encrypted_pending_request_id_data = sgxsd_jni_to_byte_array(env, response.encrypted_pending_request_id.data, sizeof(response.encrypted_pending_request_id.data));
                jbyteArray j_encrypted_pending_request_id_iv = sgxsd_jni_to_byte_array(env, response.encrypted_pending_request_id.iv.data, sizeof(response.encrypted_pending_request_id.iv.data));
                jbyteArray j_encrypted_pending_request_id_mac = sgxsd_jni_to_byte_array(env, response.encrypted_pending_request_id.mac.data, sizeof(response.encrypted_pending_request_id.mac.data));

                 // do the null checking and throwing an exception in the java constructor
                jobject j_response =
                    sgxsd_jni_new_object_by_name(env, SGXSD_JNI_PACKAGE_STR "SgxRequestNegotiationResponse", "([B[B[B[B[B)V",
                                                 j_server_static_pubkey, j_server_ephemeral_pubkey, j_encrypted_pending_request_id_data, j_encrypted_pending_request_id_iv, j_encrypted_pending_request_id_mac);
                return j_response;
            } else {
                sgxsd_jni_throw_sgxsd_exception(env, "negotiate_request_fail", negotiate_request_res);
                return NULL;
            }
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "ecall_fail", negotiate_request_ecall_res);
            return NULL;
        }
    } else {
        // an exception occurred
        return NULL;
    }
}

JNIEXPORT jlong JNICALL SGXSD_JNI_CLASS_METHOD(nativeServerStart)
    (JNIEnv *env, jclass class, jlong j_enclave_id, jlong j_server_state, jint j_max_ab_jids) {
    sgx_enclave_id_t enclave_id = j_enclave_id;
    sgxsd_server_state_handle_t server_state = j_server_state;

    sabd_start_args_t sabd_start_args = {
        .max_ab_jids = j_max_ab_jids,
    };
    sgx_status_t server_start_res;
    sgx_status_t server_start_ecall_res =
      sgxsd_enclave_server_start(enclave_id, &server_start_res, &sabd_start_args, server_state);

    if (server_start_ecall_res == SGX_SUCCESS) {
      if (server_start_res == SGX_SUCCESS) {
        jlong j_server_state = (jlong) server_state;
        return j_server_state;
      } else {
        sgxsd_jni_throw_sgxsd_exception(env, "server_start_fail", server_start_res);
        return (jlong) NULL;
      }
    } else {
      sgxsd_jni_throw_sgxsd_exception(env, "ecall_fail", server_start_ecall_res);
      return (jlong) NULL;
    }
}

void sgxsd_jni_server_call(JNIEnv *env, sgx_enclave_id_t enclave_id, sgxsd_server_state_handle_t server_state,
                           const void *args, size_t args_size,
                           const uint8_t *msg_data, size_t msg_size,
                           sgxsd_aes_gcm_iv_t msg_iv, sgxsd_aes_gcm_mac_t msg_mac,
                           sgxsd_pending_request_id_t pending_request_id,
                           jobject j_callback_obj,
                           jmethodID j_callback_method_id) {
    sgxsd_jni_msg_tag_t *p_jni_msg_tag = malloc(sizeof(sgxsd_jni_msg_tag_t));
    if (p_jni_msg_tag != NULL) {
        jobject j_callback_ref = (*env)->NewGlobalRef(env, j_callback_obj);
        (*env)->DeleteLocalRef(env, j_callback_obj);

        *p_jni_msg_tag = (sgxsd_jni_msg_tag_t) {
            .j_callback_ref = j_callback_ref,
            .j_callback_method_id = j_callback_method_id,
        };

        sgxsd_msg_tag_t msg_tag = { .p_tag = p_jni_msg_tag };
        sgxsd_msg_header_t msg_header = {
          .iv = msg_iv,
          .mac = msg_mac,
          .pending_request_id = pending_request_id,
        };

        sgx_status_t call_res;
        sgx_status_t call_ecall_res =
            sgxsd_enclave_server_call(enclave_id, &call_res, args, &msg_header, msg_data, msg_size, msg_tag, server_state);
    
        if (call_ecall_res == SGX_SUCCESS) {
            if (call_res == SGX_SUCCESS) {
                return;
            } else {
                (*env)->DeleteGlobalRef(env, p_jni_msg_tag->j_callback_ref);
                free(p_jni_msg_tag);
                sgxsd_jni_throw_sgxsd_exception(env, "server_call_fail", call_res);
                return;
            }
        } else {
            (*env)->DeleteGlobalRef(env, p_jni_msg_tag->j_callback_ref);
            free(p_jni_msg_tag);
            sgxsd_jni_throw_sgxsd_exception(env, "ecall_fail", call_ecall_res);
            return;
        }
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "malloc_fail", errno);
        return;
    }
}

JNIEXPORT void JNICALL SGXSD_JNI_CLASS_METHOD(nativeServerCall)
     (JNIEnv *env, jclass class, jlong j_enclave_id, jlong j_server_state, jint j_ab_jid_count,
      jbyteArray j_msg_data, jbyteArray j_msg_iv, jbyteArray j_msg_mac, jbyteArray j_pending_request_id,
      jobject j_callback_obj) {
    if (j_msg_data == NULL ||
        j_msg_iv == NULL ||
        j_msg_mac == NULL ||
        j_pending_request_id == NULL ||
        j_callback_obj == NULL) {
        sgxsd_jni_throw_exception(env, "java/lang/NullPointerException", "()V");
        return;
    }

    g_sgxsd_thread_jni_env = env;

    sgx_enclave_id_t enclave_id = j_enclave_id;
    sgxsd_server_state_handle_t server_state = j_server_state;

    sabd_call_args_t sabd_call_args = {
        .ab_jid_count = j_ab_jid_count,
    };

    sgxsd_aes_gcm_iv_t msg_iv;
    (*env)->GetByteArrayRegion(env, j_msg_iv, 0, sizeof(msg_iv.data), (void *) &msg_iv.data);
    (*env)->DeleteLocalRef(env, j_msg_iv);

    sgxsd_aes_gcm_mac_t msg_mac;
    (*env)->GetByteArrayRegion(env, j_msg_mac, 0, sizeof(msg_mac.data), (void *) &msg_mac.data);
    (*env)->DeleteLocalRef(env, j_msg_mac);

    sgxsd_pending_request_id_t pending_request_id;
    (*env)->GetByteArrayRegion(env, j_pending_request_id, 0, sizeof(pending_request_id), (void *) &pending_request_id);
    (*env)->DeleteLocalRef(env, j_pending_request_id);

    jmethodID j_callback_method_id;
    jclass j_callback_class = (*env)->GetObjectClass(env, j_callback_obj);
    if (j_callback_class == NULL) {
        // an exception occurred
        return;
    }
    j_callback_method_id = (*env)->GetMethodID(env, j_callback_class, "receiveServerReply", "([B[B[B)V");
    (*env)->DeleteLocalRef(env, j_callback_class);

    if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
        size_t msg_size;
        uint8_t *msg_data = sgxsd_jni_copy_byte_array(env, j_msg_data, &msg_size);
        if (msg_data != NULL) {
          sgxsd_jni_server_call(env, enclave_id, server_state, &sabd_call_args, sizeof(sabd_call_args), msg_data, msg_size, msg_iv, msg_mac, pending_request_id, j_callback_obj, j_callback_method_id);
          free(msg_data);
          return;
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "bad_msg_data", 0);
            return;
        }
    } else {
        // exception was thrown
        return;
    }
}

JNIEXPORT void JNICALL SGXSD_JNI_CLASS_METHOD(nativeServerStop)
    (JNIEnv *env, jclass class, jlong j_enclave_id, jlong j_server_state, jobject j_in_jids, jlong j_in_jid_count) {
    if (j_in_jids == NULL) {
        sgxsd_jni_throw_exception(env, "java/lang/NullPointerException", "()V");
        return;
    }

    g_sgxsd_thread_jni_env = env;

    sgx_enclave_id_t enclave_id = j_enclave_id;
    sgxsd_server_state_handle_t server_state = (sgxsd_server_state_handle_t) j_server_state;

    void *in_jids = (*env)->GetDirectBufferAddress(env, j_in_jids);
    if (in_jids != NULL) {
        jlong j_in_jids_capacity = (*env)->GetDirectBufferCapacity(env, j_in_jids);
        if (j_in_jid_count <= j_in_jids_capacity / 8) {
            sabd_stop_args_t sabd_stop_args = {
                .in_jids = in_jids,
                .in_jid_count = j_in_jid_count,
            };

            sgx_status_t stop_res;
            sgx_status_t stop_ecall_res =
                sgxsd_enclave_server_stop(enclave_id, &stop_res, &sabd_stop_args, server_state);

            if (stop_ecall_res == SGX_SUCCESS) {
                if (stop_res == SGX_SUCCESS) {
                    return;
                } else {
                    sgxsd_jni_throw_sgxsd_exception(env, "server_stop_fail", stop_res);
                    return;
                }
            } else {
                sgxsd_jni_throw_sgxsd_exception(env, "ecall_fail", stop_ecall_res);
                return;
            }
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "bad_in_jid_count", 0);
            return;
        }
    } else {
        sgxsd_jni_throw_sgxsd_exception(env, "bad_in_jids", 0);
        return;
    }
}

JNIEXPORT jint JNICALL SGXSD_JNI_CLASS_METHOD(nativeReportPlatformAttestationStatus)
    (JNIEnv *env, jclass class, jbyteArray j_platform_info, jboolean j_attestation_successful) {
    if (j_platform_info == NULL) {
        sgxsd_jni_throw_exception(env, "java/lang/NullPointerException", "()V");
        return 0;
    }

    sgx_platform_info_t platform_info;
    (*env)->GetByteArrayRegion(env, j_platform_info, 0, sizeof(platform_info.platform_info), (void *) &platform_info.platform_info);
    bool attestation_successful = j_attestation_successful;
    sgx_update_info_bit_t update_info = {0};

    if ((*env)->ExceptionCheck(env) != JNI_TRUE) {
        sgx_status_t report_status_res =
            sgx_report_attestation_status(&platform_info, !attestation_successful, &update_info);
        if (report_status_res == SGX_SUCCESS) {
            return 0;
        } else if (report_status_res == SGX_ERROR_UPDATE_NEEDED) {
            return (!!update_info.ucodeUpdate) | (!!update_info.csmeFwUpdate) << 1 | (!!update_info.pswUpdate) << 2;
        } else {
            sgxsd_jni_throw_sgxsd_exception(env, "report_attestation_status_fail", report_status_res);
            return 0;
        }
    } else {
        return 0;
    }
}
