// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::mem::size_of;
use std::sync::Arc;

use jni::objects::*;
use jni::sys::*;
use jni::{sys, Executor, JNIEnv};
use sgx_sdk_ffi::{SgxEnclaveId, SgxStatus};

use cds_enclave_ffi::sgxsd::{self, MessageReply, SgxsdError};

use crate::{
    convert_native_handle_to_directory_map_reference, generic_exception, jni_catch, sgx_name_code_to_exception, DirectoryMap,
    PossibleError, NULL_POINTER_EXCEPTION_CLASS, RUNTIME_EXCEPTION_CLASS,
};

const SGX_NEGOTIATION_RESPONSE_CLASS: &'static str = "org/whispersystems/contactdiscovery/enclave/SgxRequestNegotiationResponse";
const SGX_NEGOTIATION_RESPONSE_CSTOR: &'static str = "([B[B[B[B[B)V";

const NATIVE_CALL_ARGS_CLASS: &'static str = "org/whispersystems/contactdiscovery/enclave/SgxEnclave$NativeServerCallArgs";

const SGXSD_MESSAGE_CLASS: &'static str = "org/whispersystems/contactdiscovery/enclave/SgxsdMessage";
const SGXSD_MESSAGE_CLASS_CSTOR: &'static str = "([B[B[B)V";

const COMPLETABLE_FUTURE_CLASS: &'static str = "java/util/concurrent/CompletableFuture";
const COMPLETABLE_FUTURE_COMPLETE_METHOD: &'static str = "complete";
const COMPLETABLE_FUTURE_COMPLETE_METHOD_SIG: &'static str = "(Ljava/lang/Object;)Z";
const COMPLETABLE_FUTURE_COMPLETE_EXCEPTIONALLY_METHOD: &'static str = "completeExceptionally";
const COMPLETABLE_FUTURE_COMPLETE_EXCEPTIONALLY_METHOD_SIG: &'static str = "(Ljava/lang/Throwable;)Z";

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeEnclaveStart<'a>(
    env: JNIEnv,
    _class: JClass<'a>,
    enclave_path: JString<'a>,
    debug: jboolean,
    pending_requests_table_order: jbyte,
    callback: JObject<'a>,
) {
    jni_catch(env.clone(), 0, || {
        enclave_start(env, enclave_path, debug == 1, pending_requests_table_order, callback)
    });
}

fn sgxstatus_to_possibleerror(name: &'static str, status: SgxStatus) -> PossibleError {
    return match status {
        SgxStatus::Success => PossibleError::Generic {
            class: RUNTIME_EXCEPTION_CLASS.to_string(),
            msg: "SgxStatus was a Success but returned as an error in".to_string() + name,
        },
        SgxStatus::Error(err) => PossibleError::SgxError { name, code: err as i64 },
        SgxStatus::Unknown(code) => PossibleError::SgxError { name, code: code as i64 },
    };
}

fn enclave_start<'a>(
    env: JNIEnv,
    enclave_path: JString,
    debug: bool,
    pending_requests_table_order: i8,
    callback: JObject<'a>,
) -> Result<i64, PossibleError> {
    if callback.is_null() {
        return Err(generic_exception(
            NULL_POINTER_EXCEPTION_CLASS,
            "EnclaveStartCallback callback was null",
        ));
    }
    let enclave_path = env.get_string(enclave_path)?;
    let enclave_path_c = enclave_path
        .to_str()
        .or(Err(generic_exception(RUNTIME_EXCEPTION_CLASS, "non-UTF8 bytes in enclave path")))?;

    let (gid, _) = sgx_sdk_ffi::init_quote().map_err(|status| sgxstatus_to_possibleerror("init_quote_before_create", status))?;

    let enclave_id = sgxsd::sgxsd_create_enclave(enclave_path_c, debug).map_err(PossibleError::from)?;
    let enclave_id_j = enclave_id as i64;
    sgxsd::sgxsd_node_init(enclave_id, pending_requests_table_order as u8)?;
    env.call_method(
        callback,
        "runEnclave",
        "(JJ)V",
        &[JValue::Long(enclave_id_j), JValue::Long(gid as i64)],
    )?;
    return sgxsd::sgxsd_destroy_enclave(enclave_id)
        .map(|_| enclave_id_j)
        .map_err(PossibleError::from);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeGetNextQuote(
    env: JNIEnv,
    class: JClass,
    enclave_id: jlong,
    spid: jbyteArray,
    sig_rl: jbyteArray,
) -> jbyteArray {
    return jni_catch(env.clone(), env.new_byte_array(0).unwrap(), || {
        get_next_quote(env, class, enclave_id, spid, sig_rl)
    });
}

fn get_next_quote(env: JNIEnv, _class: JClass, enclave_id: i64, spid: jbyteArray, sig_rl: jbyteArray) -> Result<jbyteArray, PossibleError> {
    let spid_dyn = jni_array_to_vec(&env, spid)?;
    if spid_dyn.len() != 16 {
        let err = PossibleError::SgxError {
            name: "spid_length_incorrect",
            code: sgx_sdk_ffi::SgxError::InvalidParameter as i64,
        };
        return Err(err);
    }
    let spid_c = &mut [0 as u8; 16];
    spid_c.copy_from_slice(spid_dyn.as_slice());

    let sig_rl_c = jni_array_to_vec(&env, sig_rl)?;

    let quote = sgxsd::sgxsd_get_next_quote(enclave_id as SgxEnclaveId, spid_c, sig_rl_c.as_slice())?;
    return slice_to_jni_array(&env, quote.data.as_slice()).map_err(PossibleError::from);
}

fn slice_to_jni_array(env: &JNIEnv, data: &[u8]) -> Result<jbyteArray, jni::errors::Error> {
    let out = env.new_byte_array(data.len() as i32)?;
    let buf: Vec<i8> = data.into_iter().map(|i| *i as i8).collect();
    env.set_byte_array_region(out, 0, buf.as_slice())?;
    Ok(out)
}

fn jni_array_to_fixed_buffer(env: &JNIEnv, jni_array: jbyteArray, out: &mut [u8]) -> Result<(), PossibleError> {
    let length = env.get_array_length(jni_array)?;
    if length as usize != out.len() {
        return Err(PossibleError::Generic {
            class: RUNTIME_EXCEPTION_CLASS.to_string(),
            msg: format!("expected {0} length, got {1} length array", out.len(), length),
        });
    }
    let outi8 = &mut vec![0 as i8; out.len()];
    env.get_byte_array_region(jni_array, 0, outi8)?;
    for (i, item) in outi8.into_iter().enumerate() {
        out[i] = *item as u8;
    }
    return Ok(());
}

fn jni_array_to_vec(env: &JNIEnv, jni_array: jbyteArray) -> Result<Vec<u8>, PossibleError> {
    let length = env.get_array_length(jni_array)?;
    let outi8 = &mut vec![0; length as usize];
    env.get_byte_array_region(jni_array, 0, outi8)?;
    let out: Vec<u8> = outi8.into_iter().map(|i| *i as u8).collect();
    return Ok(out);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeSetCurrentQuote(
    env: JNIEnv,
    _class: JClass,
    enclave_id: jlong,
) {
    jni_catch(env.clone(), (), || set_current_quote(enclave_id))
}

fn set_current_quote(enclave_id: jlong) -> Result<(), PossibleError> {
    return sgxsd::sgxsd_set_current_quote(enclave_id as u64).map_err(PossibleError::from);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeNegotiateRequest(
    env: JNIEnv,
    _class: JClass,
    enclave_id: jlong,
    client_pubkey: jbyteArray,
) -> jni::sys::jobject {
    return jni_catch(env.clone(), JObject::null().into_inner(), || {
        negotiate_request(&env, enclave_id, client_pubkey)
    });
}

fn negotiate_request(env: &JNIEnv, enclave_id: i64, client_pubkey: jbyteArray) -> Result<sys::jobject, PossibleError> {
    let pubkey = jni_array_to_vec(&env, client_pubkey)?;
    if pubkey.len() as u32 != sgxsd::SGXSD_CURVE25519_KEY_SIZE {
        return Err(PossibleError::SgxError {
            name: "negotiate_request_client_pubkey_copy",
            code: sgx_sdk_ffi::SgxError::InvalidParameter as i64,
        });
    }
    let pubkey_c = &mut [0 as u8; 32];
    pubkey_c.copy_from_slice(pubkey.as_slice());
    let request = sgxsd::SgxsdRequestNegotiationRequest {
        client_pubkey: sgxsd::SgxsdCurve25519PublicKey { x: *pubkey_c },
    };
    let resp = sgxsd::sgxsd_negotiate_request(enclave_id as u64, &request)?;
    let server_static = slice_to_jni_array(&env, &resp.server_static_pubkey.x[..])?;
    let server_ephemeral = slice_to_jni_array(&env, &resp.server_ephemeral_pubkey.x[..])?;
    let data = slice_to_jni_array(&env, &resp.encrypted_pending_request_id.data[..])?;
    let iv = slice_to_jni_array(&env, &resp.encrypted_pending_request_id.iv.data[..])?;
    let mac = slice_to_jni_array(&env, &resp.encrypted_pending_request_id.mac.data[..])?;
    let args = &[
        JValue::from(server_static),
        JValue::from(server_ephemeral),
        JValue::from(data),
        JValue::from(iv),
        JValue::from(mac),
    ];
    return env
        .new_object(SGX_NEGOTIATION_RESPONSE_CLASS, SGX_NEGOTIATION_RESPONSE_CSTOR, args)
        .map(|o| o.into_inner())
        .map_err(PossibleError::from);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeServerStart(
    env: JNIEnv,
    _class: JClass,
    enclave_id: jlong,
    state_handle: jlong,
    max_query_phones: jint,
) {
    return jni_catch(env.clone(), (), || server_start(env, enclave_id, state_handle, max_query_phones));
}

fn server_start(_env: JNIEnv, enclave_id: i64, state_handle: i64, max_query_phones: i32) -> Result<(), PossibleError> {
    let args = sgxsd::SgxsdServerInitArgs {
        max_query_phones: max_query_phones as u32,
        max_ratelimit_states: 0,
    };
    return sgxsd::sgxsd_server_start(enclave_id as u64, &args, state_handle as u64).map_err(PossibleError::from);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeServerCall(
    env: JNIEnv,
    _class: JClass,
    enclave_id: jlong,
    state_handle: jlong,
    args: JObject,
    future: JObject,
) {
    return jni_catch(env.clone(), (), || server_call(env, enclave_id, state_handle, args, future));
}

fn server_call(env: JNIEnv, enclave_id: i64, state_handle: i64, args: JObject, future: JObject) -> Result<(), PossibleError> {
    let is_instance = env.is_instance_of(args, NATIVE_CALL_ARGS_CLASS)?;
    if !is_instance {
        return Err(generic_exception(
            RUNTIME_EXCEPTION_CLASS,
            "server_call called with an incorrect callback arguments type",
        ));
    }
    if !env.is_instance_of(future, COMPLETABLE_FUTURE_CLASS)? {
        return Err(generic_exception(
            RUNTIME_EXCEPTION_CLASS,
            "server_call called with an incorrect future argument type",
        ));
    }
    let msg_data = jni_array_to_vec(&env, get_nonnull_byte_array_field(&env, args, "msg_data")?)?;
    if msg_data.len() == 0 {
        return Err(PossibleError::SgxError {
            name: "bad_msg_data",
            code: 0,
        });
    }
    let mut query_data = jni_array_to_vec(&env, get_nonnull_byte_array_field(&env, args, "query_data")?)?;
    if query_data.len() == 0 {
        return Err(PossibleError::SgxError {
            name: "bad_query_data",
            code: 0,
        });
    }
    let msg_iv = &mut [0 as u8; size_of::<sgxsd::SgxsdAesGcmIv>()];
    get_nonnull_fixed_size_array_field(&env, args, "msg_iv", &mut msg_iv[..])?;
    let msg_mac = &mut [0 as u8; size_of::<sgxsd::SgxsdAesGcmMac>()];
    get_nonnull_fixed_size_array_field(&env, args, "msg_mac", &mut msg_mac[..])?;

    let query_phone_count = env.get_field(args, "query_phone_count", "I")?.i()?;

    let query_iv = &mut [0 as u8; size_of::<sgxsd::SgxsdAesGcmIv>()];
    get_nonnull_fixed_size_array_field(&env, args, "query_iv", &mut query_iv[..])?;
    let query_mac = &mut [0 as u8; size_of::<sgxsd::SgxsdAesGcmMac>()];
    get_nonnull_fixed_size_array_field(&env, args, "query_mac", &mut query_mac[..])?;
    let query_commitment = &mut [0 as u8; sgxsd::SGXSD_SHA256_HASH_SIZE as usize];
    get_nonnull_fixed_size_array_field(&env, args, "query_commitment", &mut query_commitment[..])?;

    // This one is weird, because the previous C code filled the sgxsd_pending_request_id_t struct directly with GetByteArrayRegion.
    // We'd like to undo the choice to serialize pending_request_id_t to this byte array, but have left
    // to avoid making a change to SgxEnclave$NativeServerCallbackArgs.
    let pending_request_id_bytes = &mut [0 as u8; size_of::<sgxsd::SgxsdPendingRequestId>()];
    get_nonnull_fixed_size_array_field(&env, args, "pending_request_id", &mut pending_request_id_bytes[..])?;

    let pending_request_id_data = &mut [0 as u8; size_of::<u64>()];
    pending_request_id_data.clone_from_slice(&pending_request_id_bytes[0..size_of::<u64>()]);

    let u64_and_iv = size_of::<u64>() + size_of::<sgxsd::SgxsdAesGcmIv>();
    let pending_request_id_iv = &mut [0 as u8; size_of::<sgxsd::SgxsdAesGcmIv>()];
    pending_request_id_iv.clone_from_slice(&pending_request_id_bytes[size_of::<u64>()..u64_and_iv]);

    let u64_iv_and_mac = u64_and_iv + size_of::<sgxsd::SgxsdAesGcmMac>();
    let pending_request_id_mac = &mut [0 as u8; size_of::<sgxsd::SgxsdAesGcmMac>()];
    pending_request_id_mac.clone_from_slice(&pending_request_id_bytes[u64_and_iv..u64_iv_and_mac]);

    let sgxcallargs = sgxsd::SgxsdServerCallArgs {
        query_phone_count: query_phone_count as u32,
        ratelimit_state_size: Default::default(),
        ratelimit_state_uuid: Default::default(),
        ratelimit_state_data: std::ptr::null_mut(),
        query: sgxsd::CDSEncryptedMsg {
            iv: sgxsd::SgxsdAesGcmIv { data: *query_iv },
            mac: sgxsd::SgxsdAesGcmMac { data: *query_mac },
            size: query_data.len() as u32,
            data: query_data.as_mut_ptr(),
        },
        query_commitment: *query_commitment,
    };
    let msg_header = sgxsd::SgxsdMessageHeader {
        iv: sgxsd::SgxsdAesGcmIv { data: *msg_iv },
        mac: sgxsd::SgxsdAesGcmMac { data: *msg_mac },
        pending_request_id: sgxsd::SgxsdPendingRequestId {
            data: *pending_request_id_data,
            iv: sgxsd::SgxsdAesGcmIv {
                data: *pending_request_id_iv,
            },
            mac: sgxsd::SgxsdAesGcmMac {
                data: *pending_request_id_mac,
            },
        },
    };

    let future_ref = env.new_global_ref(future)?;
    let jvm = env.get_java_vm()?;
    let exec = Executor::new(Arc::new(jvm));
    // This won't be run on the same thread necessarily, so we have to do the Executor work.
    // Plus, we can't use the return values it has.
    let reply_fun = move |res: sgxsd::SgxsdResult<sgxsd::MessageReply>| -> () {
        let _ignored = match res {
            Ok(reply) => {
                exec.with_attached(|local_env| complete_future_successfully(local_env, reply, future_ref))
                    .map_err(|e| {
                        // Because this is a full-on JNI error inside of a callback that's run in a
                        // different thread inside the enclave that happens when we're already trying to
                        // signal a status back to the original JVM caller, all we can do is print
                        // here.
                        eprintln!(
                            "SEVERE: got a JNI error when trying to complete the SGX future successfully in server_stop: {:?}",
                            e
                        );
                    })
            }
            Err(sgxerr) => {
                exec.with_attached(|local_env| {
                    complete_future_exceptionally_with_sgxerr(local_env, "server_stop", future_ref, sgxerr)
                }).map_err(|e| {
                    // Because this is a full-on JNI error inside of a callback that's run in a
                    // different thread inside the enclave that happens when we're already trying to
                    // signal a failure back to the original JVM caller, all we can do is print
                    // here.
                    eprintln!("SEVERE: got a JNI error when trying to complete the SGX future exceptionally with SGX error {:?} in server_stop: {:?}", sgxerr, e);
                })
            }
        };
    };

    return sgxsd::sgxsd_server_call(
        enclave_id as u64,
        sgxcallargs,
        &msg_header,
        msg_data.as_slice(),
        reply_fun,
        state_handle as u64,
    )
    .map_err(PossibleError::from);
}

fn complete_future_successfully(env: &JNIEnv, reply: MessageReply, future_ref: GlobalRef) -> Result<(), jni::errors::Error> {
    let data = slice_to_jni_array(&env, &reply.data)?;
    let iv = slice_to_jni_array(&env, &reply.iv.data)?;
    let mac = slice_to_jni_array(&env, &reply.mac.data)?;
    let args: Vec<JValue> = vec![data, iv, mac].into_iter().map(JValue::from).collect();
    let msg = env.new_object(SGXSD_MESSAGE_CLASS, SGXSD_MESSAGE_CLASS_CSTOR, &args)?;
    let complete_args: &[JValue] = &[msg.into()];
    return env
        .call_method(
            future_ref.as_obj(),
            COMPLETABLE_FUTURE_COMPLETE_METHOD,
            COMPLETABLE_FUTURE_COMPLETE_METHOD_SIG,
            complete_args,
        )
        .map(|_| ());
}

fn complete_future_exceptionally_with_sgxerr(
    env: &JNIEnv,
    step_name: &'static str,
    future_ref: GlobalRef,
    sgxerr: SgxsdError,
) -> Result<(), jni::errors::Error> {
    let posserr = sgxstatus_to_possibleerror(step_name, sgxerr.status);
    let exc = match posserr {
        PossibleError::Generic { class, msg } => env.new_string(msg).and_then(|jmsg| {
            return env.new_object(class, "(Ljava.lang.String)V", &[jmsg.into()]);
        })?,
        PossibleError::SgxError { name, code } => sgx_name_code_to_exception(env, name, code)?,
        PossibleError::AlreadyThrown(_) => env
            .new_string("SEVERE: An SGXStatus somehow became a jni::errors::Error in the JNI code")
            .and_then(|jmsg| {
                return env.new_object(RUNTIME_EXCEPTION_CLASS, "(Ljava.lang.String)V", &[jmsg.into()]);
            })?,
    };
    let args: &[JValue] = &[exc.into()];
    return env
        .call_method(
            future_ref.as_obj(),
            COMPLETABLE_FUTURE_COMPLETE_EXCEPTIONALLY_METHOD,
            COMPLETABLE_FUTURE_COMPLETE_EXCEPTIONALLY_METHOD_SIG,
            args,
        )
        .map(|_| ());
}

fn get_nonnull_fixed_size_array_field(env: &JNIEnv, obj: JObject, field_name: &str, buf: &mut [u8]) -> Result<(), PossibleError> {
    let array = get_nonnull_byte_array_field(&env, obj, field_name)?;
    return jni_array_to_fixed_buffer(&env, array, buf);
}

fn get_nonnull_byte_array_field(env: &JNIEnv, obj: JObject, field_name: &str) -> Result<jbyteArray, PossibleError> {
    let field_obj = env.get_field(obj, field_name, "[B")?.l()?;
    if field_obj.is_null() {
        return Err(PossibleError::Generic {
            class: NULL_POINTER_EXCEPTION_CLASS.to_string(),
            msg: field_name.to_string() + " was null",
        });
    }

    return Ok(field_obj.into_inner() as jbyteArray);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeServerStop(
    env: JNIEnv,
    _class: JClass,
    enclave_id: jlong,
    state_handle: jlong,
    directory_map_handle: jlong,
) {
    return jni_catch(env.clone(), (), || {
        if directory_map_handle != 0 {
            let directory_map = convert_native_handle_to_directory_map_reference(directory_map_handle)?;
            server_stop(enclave_id, state_handle, directory_map)
        } else {
            server_stop_no_directory_map(enclave_id, state_handle)
        }
    });
}

fn server_stop(enclave_id: i64, state_handle: i64, directory_map: &DirectoryMap) -> Result<(), PossibleError> {
    directory_map.borrow_serving_buffers(|e164s, uuids| {
        if e164s.len() != uuids.len() {
            return Err(PossibleError::SgxError {
                name: "e164s_and_uuids_buffer_length_mismatch",
                code: 0,
            });
        }
        let args = sgxsd::ServerStopArgs {
            in_phones: &e164s[0],
            in_uuids: &uuids[0],
            in_phone_count: e164s.len() as u64,
        };
        Ok(sgxsd::sgxsd_server_stop(enclave_id as u64, &args, state_handle as u64)?)
    })
}

fn server_stop_no_directory_map(enclave_id: i64, state_handle: i64) -> Result<(), PossibleError> {
    let args = sgxsd::ServerStopArgs {
        in_phones: std::ptr::null(),
        in_uuids: std::ptr::null(),
        in_phone_count: 0,
    };
    Ok(sgxsd::sgxsd_server_stop(enclave_id as u64, &args, state_handle as u64)?)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_org_whispersystems_contactdiscovery_enclave_SgxEnclave_nativeReportPlatformAttestationStatus(
    env: JNIEnv,
    _class: JClass,
    platform_info: jbyteArray,
    attestation_successful: jboolean,
) -> jint {
    return jni_catch(env.clone(), 0, || {
        report_platform_attestation_status(env, platform_info, attestation_successful != 0)
    });
}

fn report_platform_attestation_status(
    env: JNIEnv,
    platform_info_bytes: jbyteArray,
    attestation_successful: bool,
) -> Result<i32, PossibleError> {
    if platform_info_bytes.is_null() {
        return Err(generic_exception(
            NULL_POINTER_EXCEPTION_CLASS,
            "platform_info array cannot be null",
        ));
    }
    let out = &mut [0 as u8; size_of::<sgxsd::SgxPlatformInfo>()];
    jni_array_to_fixed_buffer(&env, platform_info_bytes, out)?;
    let info = sgxsd::SgxPlatformInfo { platform_info: *out };
    return sgxsd::sgxsd_report_attestation_status(&info, attestation_successful)
        .map(|attest_status| {
            match attest_status {
                sgxsd::AttestationStatus::NoUpdateNeeded => 0,
                sgxsd::AttestationStatus::UpdateNeeded(update_info) => {
                    // This matches the SgxNeedsUpdateFlag Java enum
                    let ucode = if update_info.ucodeUpdate != 0 { 1 } else { 0 };
                    let csmefw = if update_info.csmeFwUpdate != 0 { 1 } else { 0 };
                    let psw = if update_info.pswUpdate != 0 { 1 } else { 0 };
                    return ucode | csmefw << 1 | psw << 2;
                }
            }
        })
        .map_err(PossibleError::from);
}
