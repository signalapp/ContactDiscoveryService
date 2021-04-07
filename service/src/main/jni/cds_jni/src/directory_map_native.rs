// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::sync::{Mutex, RwLock};

use byteorder::{BigEndian, ByteOrder};
use jni::objects::{JClass, JValue};
use jni::sys::{jboolean, jlong, jobject};
use jni::JNIEnv;

use internal_buffers::InternalBuffers;

use crate::{bool_to_jni_bool, generic_exception, jni_catch, PossibleError, ILLEGAL_STATE_EXCEPTION_CLASS, NULL_POINTER_EXCEPTION_CLASS};

mod internal_buffers;

fn convert_native_handle_to_directory_map_reference(native_handle: jlong) -> Result<&'static mut DirectoryMap, PossibleError> {
    if native_handle == 0 {
        Err(generic_exception(NULL_POINTER_EXCEPTION_CLASS, "native_handle is null"))
    } else {
        Ok(unsafe { &mut *(native_handle as *mut DirectoryMap) })
    }
}

struct DirectoryMapBuilding(RefCell<bool>, RefCell<InternalBuffers>);

struct DirectoryMap {
    building: Mutex<DirectoryMapBuilding>,
    serving: RwLock<RefCell<InternalBuffers>>,
}

impl DirectoryMap {
    fn new(capacity: usize) -> Self {
        Self {
            building: Mutex::new(DirectoryMapBuilding(
                RefCell::new(false),
                RefCell::new(InternalBuffers::new(capacity)),
            )),
            serving: RwLock::new(RefCell::new(InternalBuffers::new(capacity))),
        }
    }

    fn insert(&self, e164: [u8; 8], uuid: [u8; 16]) -> Result<bool, PossibleError> {
        let lock = self
            .building
            .lock()
            .expect("DirectoryMap building lock poisoned while locking during insert");
        let mut internal_buffers = lock.1.borrow_mut();
        let added = internal_buffers.insert(e164, uuid)?;
        if added {
            *lock.0.borrow_mut() = true;
        }
        Ok(added)
    }

    fn remove(&self, e164: [u8; 8]) -> Result<bool, PossibleError> {
        let lock = self
            .building
            .lock()
            .expect("DirectoryMap building lock poisoned while locking during remove");
        let mut internal_buffers = lock.1.borrow_mut();
        let removed = internal_buffers.remove(e164)?;
        if removed {
            *lock.0.borrow_mut() = true;
        }
        Ok(removed)
    }

    fn run_borrow_function(&self, borrow_function: impl FnOnce(&[u8], &[u8]) -> Result<(), PossibleError>) -> Result<(), PossibleError> {
        let read_lock = self
            .serving
            .read()
            .expect("DirectoryMap serving read lock poisoned while locking during run_borrow_function");
        let internal_buffers = RefCell::<InternalBuffers>::borrow(&read_lock);
        borrow_function(internal_buffers.e164s_slice(), internal_buffers.uuids_slice())
    }

    fn commit(&self) -> Result<bool, PossibleError> {
        let lock = self
            .building
            .lock()
            .expect("DirectoryMap building lock poisoned while locking during commit");
        if !*lock.0.borrow() {
            return Ok(false);
        }
        {
            let write_lock = self
                .serving
                .write()
                .expect("DirectoryMap serving write lock poisoned while locking during commit");
            lock.1.swap(&*write_lock);
        }
        {
            let read_lock = self
                .serving
                .read()
                .expect("DirectoryMap serving read lock poisoned while locking during commit");
            lock.1.borrow_mut().copy_from(&*RefCell::<InternalBuffers>::borrow(&read_lock))?;
        }
        *lock.0.borrow_mut() = false;
        return Ok(true);
    }

    fn size(&self) -> usize {
        RefCell::<InternalBuffers>::borrow(
            &self
                .serving
                .read()
                .expect("DirectoryMap serving read lock poisoned while locking during size"),
        )
        .size()
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_org_whispersystems_contactdiscovery_directory_DirectoryMapNative_nativeInit(
    _env: JNIEnv,
    _class: JClass,
    capacity: jlong,
) -> jlong {
    Box::into_raw(Box::new(DirectoryMap::new(capacity as usize))) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_org_whispersystems_contactdiscovery_directory_DirectoryMapNative_nativeFree(
    _env: JNIEnv,
    _class: JClass,
    native_handle: jlong,
) {
    let _box = unsafe { Box::from_raw(native_handle as *mut DirectoryMap) };
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_org_whispersystems_contactdiscovery_directory_DirectoryMapNative_nativeInsert(
    env: JNIEnv,
    _class: JClass,
    native_handle: jlong,
    e164: jlong,
    uuid: jobject,
) -> jboolean {
    bool_to_jni_bool(jni_catch(env.clone(), false, || {
        let directory_map = convert_native_handle_to_directory_map_reference(native_handle)?;
        let mut e164_bytes = [0; 8];
        BigEndian::write_i64(&mut e164_bytes, e164);
        let uuid_high_bits = env.call_method(uuid, "getMostSignificantBits", "()J", &[])?.j().unwrap();
        let uuid_low_bits = env.call_method(uuid, "getLeastSignificantBits", "()J", &[])?.j().unwrap();
        let mut uuid_bytes = [0; 16];
        BigEndian::write_i64(&mut uuid_bytes[..8], uuid_high_bits);
        BigEndian::write_i64(&mut uuid_bytes[8..], uuid_low_bits);
        Ok(directory_map.insert(e164_bytes, uuid_bytes)?)
    }))
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_org_whispersystems_contactdiscovery_directory_DirectoryMapNative_nativeRemove(
    env: JNIEnv,
    _class: JClass,
    native_handle: jlong,
    e164: jlong,
) -> jboolean {
    bool_to_jni_bool(jni_catch(env.clone(), false, || {
        let directory_map = convert_native_handle_to_directory_map_reference(native_handle)?;
        let mut e164_bytes = [0; 8];
        BigEndian::write_i64(&mut e164_bytes, e164);
        Ok(directory_map.remove(e164_bytes)?)
    }))
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_org_whispersystems_contactdiscovery_directory_DirectoryMapNative_nativeBorrow(
    env: JNIEnv,
    _class: JClass,
    native_handle: jlong,
    borrow_function: jobject,
) {
    jni_catch(env.clone(), (), || {
        let directory_map = convert_native_handle_to_directory_map_reference(native_handle)?;
        directory_map.run_borrow_function(|e164s, uuids| {
            if e164s.len() * 2 != uuids.len() {
                return Err(generic_exception(
                    ILLEGAL_STATE_EXCEPTION_CLASS,
                    "e164 slice should be half as long as uuids slice",
                ));
            }
            if e164s.len() % 8 != 0 {
                return Err(generic_exception(
                    ILLEGAL_STATE_EXCEPTION_CLASS,
                    "e164 slice should be a multiple of 8 bytes long",
                ));
            }
            if uuids.len() % 16 != 0 {
                // this isn't theoretically possible given the above two checks, but included for
                // completeness
                return Err(generic_exception(
                    ILLEGAL_STATE_EXCEPTION_CLASS,
                    "uuid slice should be a multiple of 16 bytes long",
                ));
            }
            env.call_method(
                borrow_function,
                "consume",
                "(JJJJ)V",
                &[
                    JValue::from(e164s.as_ptr() as jlong),
                    JValue::from(e164s.len() as jlong),
                    JValue::from(uuids.as_ptr() as jlong),
                    JValue::from(uuids.len() as jlong),
                ],
            )?;
            Ok(())
        })?;
        Ok(())
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_org_whispersystems_contactdiscovery_directory_DirectoryMapNative_nativeCommit(
    env: JNIEnv,
    _class: JClass,
    native_handle: jlong,
) -> jboolean {
    bool_to_jni_bool(jni_catch(env.clone(), false, || {
        let directory_map = convert_native_handle_to_directory_map_reference(native_handle)?;
        Ok(directory_map.commit()?)
    }))
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_org_whispersystems_contactdiscovery_directory_DirectoryMapNative_nativeSize(
    env: JNIEnv,
    _class: JClass,
    native_handle: jlong,
) -> jlong {
    jni_catch(env.clone(), 0, || {
        let directory_map = convert_native_handle_to_directory_map_reference(native_handle)?;
        Ok(directory_map.size() as jlong)
    })
}
