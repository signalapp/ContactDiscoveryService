// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::panic::{catch_unwind, UnwindSafe};

use jni::objects::{JObject, JThrowable, JValue};
use jni::sys::{jboolean, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use sgx_sdk_ffi::SgxStatus;
use thiserror::Error as ThisError;

use cds_enclave_ffi::sgxsd;
use directory_map_native::{convert_native_handle_to_directory_map_reference, DirectoryMap};

mod directory_map_native;
mod sgx_enclave;

const SGX_EXCEPTION_CLASS: &'static str = "org/whispersystems/contactdiscovery/enclave/SgxException";
const SGX_EXCEPTION_CSTOR: &'static str = "(Ljava/lang/String;J)V";

const NULL_POINTER_EXCEPTION_CLASS: &'static str = "java/lang/NullPointerException";
const RUNTIME_EXCEPTION_CLASS: &'static str = "java/lang/RuntimeException";

#[derive(ThisError, Debug)]
enum PossibleError {
    // FIXME handle more than just SgxException in server callbacks or maybe not?
    #[error("Exception raised inside CDS JNI, class `{0}`, msg `{1}`", .class, .msg)]
    Generic { class: String, msg: String },
    #[error("SGX call for {0} failed with code {1}", .name, .code)]
    SgxError { name: &'static str, code: i64 },
    #[error("Already thrown Java exception")]
    AlreadyThrown(jni::errors::Error),
}

impl From<jni::errors::Error> for PossibleError {
    fn from(e: jni::errors::Error) -> Self {
        Self::AlreadyThrown(e)
    }
}

impl From<sgxsd::SgxsdError> for PossibleError {
    fn from(e: sgxsd::SgxsdError) -> Self {
        let name = e.name;
        let code = match e.status {
            SgxStatus::Success => panic!("SgxsdError had a successful state"),
            SgxStatus::Error(err) => err as i64,
            SgxStatus::Unknown(code) => code as i64,
        };
        return Self::SgxError { name, code };
    }
}

fn throw_sgx_name_code_to_exception(env: JNIEnv, name: &'static str, code: i64) -> Result<(), jni::errors::Error> {
    sgx_name_code_to_exception(&env, name, code)
        .map(|exc| env.throw(JThrowable::from(exc)))
        .map(|_| ())
}

fn sgx_name_code_to_exception<'a>(env: &JNIEnv<'a>, name: &str, code: i64) -> Result<JObject<'a>, jni::errors::Error> {
    env.new_string(name).and_then(|jstr| {
        let args = &[JValue::Object(jstr.into()), JValue::Long(code)];
        env.new_object(SGX_EXCEPTION_CLASS.to_string(), SGX_EXCEPTION_CSTOR.to_string(), args)
    })
}

fn bool_to_jni_bool(b: bool) -> jboolean {
    if b {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

fn jni_catch<'a, T>(env: JNIEnv, default: T, fun: impl FnOnce() -> Result<T, PossibleError> + UnwindSafe) -> T {
    match catch_unwind(fun) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            match error {
                PossibleError::Generic { class, msg } => {
                    env.throw_new(class, msg).map_err(|e| {
                        // This JNI error occurred while trying to tell the JNI an error occurred,
                        // so we can't do more than this
                        panic!("SEVERE: JNI error occurred while trying to throw a generic exception: {}", e)
                    });
                }
                PossibleError::SgxError { name, code } => {
                    throw_sgx_name_code_to_exception(env, name, code).map_err(|e| {
                        // This JNI error occurred while trying to tell the JNI an error occurred,
                        // so we can't do more than this
                        panic!(
                            "SEVERE: JNI error occurred while trying to throw the SGX exception ({}, {}): {}",
                            name, code, e
                        )
                    });
                }
                PossibleError::AlreadyThrown(_err) => {
                    // do nothing, it's already been thrown
                }
            }
            default
        }
        Err(_) => {
            let _ignore = env.exception_check().and_then(|jni_has_exc| {
                if !jni_has_exc {
                    return env.throw_new(RUNTIME_EXCEPTION_CLASS, "rust panicked");
                }
                Ok(())
            });
            default
        }
    }
}

fn generic_exception(class: &str, msg: &str) -> PossibleError {
    PossibleError::Generic {
        class: class.to_string(),
        msg: msg.to_string(),
    }
}
