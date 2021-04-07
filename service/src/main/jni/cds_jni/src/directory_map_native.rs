// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Mutex, RwLock};

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

struct DirectoryMapBuilding(bool, InternalBuffers);

struct DirectoryMap {
    building: Mutex<DirectoryMapBuilding>,
    serving: RwLock<InternalBuffers>,
}

impl DirectoryMap {
    fn new(capacity: usize) -> Self {
        Self {
            building: Mutex::new(DirectoryMapBuilding(false, InternalBuffers::new(capacity))),
            serving: RwLock::new(InternalBuffers::new(capacity)),
        }
    }

    fn insert(&self, e164: [u8; 8], uuid: [u8; 16]) -> Result<bool, PossibleError> {
        let mut lock = self
            .building
            .lock()
            .expect("DirectoryMap building lock poisoned while locking during insert");
        let added = lock.1.insert(e164, uuid)?;
        if added {
            lock.0 = true;
        }
        Ok(added)
    }

    fn remove(&self, e164: [u8; 8]) -> Result<bool, PossibleError> {
        let mut lock = self
            .building
            .lock()
            .expect("DirectoryMap building lock poisoned while locking during remove");
        let removed = lock.1.remove(e164)?;
        if removed {
            lock.0 = true;
        }
        Ok(removed)
    }

    fn run_borrow_function(&self, borrow_function: impl FnOnce(&[u8], &[u8]) -> Result<(), PossibleError>) -> Result<(), PossibleError> {
        let read_lock = self
            .serving
            .read()
            .expect("DirectoryMap serving read lock poisoned while locking during run_borrow_function");
        borrow_function(read_lock.e164s_slice(), read_lock.uuids_slice())
    }

    fn commit(&self) -> Result<bool, PossibleError> {
        let mut lock = self
            .building
            .lock()
            .expect("DirectoryMap building lock poisoned while locking during commit");
        if !lock.0 {
            return Ok(false);
        }
        {
            let mut write_lock = self
                .serving
                .write()
                .expect("DirectoryMap serving write lock poisoned while locking during commit");
            std::mem::swap(&mut lock.1, &mut *write_lock);
        }
        {
            let read_lock = self
                .serving
                .read()
                .expect("DirectoryMap serving read lock poisoned while locking during commit");
            lock.1.copy_from(&*read_lock)?;
        }
        lock.0 = false;
        return Ok(true);
    }

    fn size(&self) -> usize {
        self.serving
            .read()
            .expect("DirectoryMap serving read lock poisoned while locking during size")
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
    // recapture ownership of native_handle into a Box and let end of scope free it
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
        let uuid_high_bits = env.call_method(uuid, "getMostSignificantBits", "()J", &[])?.j().unwrap();
        let uuid_low_bits = env.call_method(uuid, "getLeastSignificantBits", "()J", &[])?.j().unwrap();
        let mut uuid_bytes = [0; 16];
        uuid_bytes[..8].copy_from_slice(&uuid_high_bits.to_be_bytes());
        uuid_bytes[8..].copy_from_slice(&uuid_low_bits.to_be_bytes());
        Ok(directory_map.insert(e164.to_be_bytes(), uuid_bytes)?)
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
        Ok(directory_map.remove(e164.to_be_bytes())?)
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

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;
    use std::convert::TryInto;

    #[test]
    fn single_element_test() {
        let e164 = [0u8, 0, 0, 0x03, 0x9F, 0x5E, 0x8B, 0x6D];
        let uuid = [
            0xDEu8, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ];

        let map = DirectoryMap::new(1000);
        assert_eq!(map.size(), 0);

        let result = map.commit();
        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(map.size(), 0);

        let result = map.insert(e164, uuid);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(map.size(), 0);

        let result = map.commit();
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(map.size(), 1);

        let result = map.remove(e164);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(map.size(), 1);

        let result = map.remove(e164);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(map.size(), 1);

        let result = map.commit();
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn borrow_function_test() {
        let map = DirectoryMap::new(1000);
        let mut set = HashSet::new();

        let number = 15555550100i64;
        let uuid = u128::from_be_bytes([
            0xd9, 0x03, 0xcd, 0x9e, 0xab, 0x77, 0x6f, 0xf5, 0x66, 0x65, 0x98, 0x89, 0x39, 0xb4, 0xe3, 0x51,
        ]);

        let number_g = 31i64;
        let uuid_g = 414094729u128;

        for i in 0..1000usize {
            set.insert(i);
            let result = map.insert(
                (number + number_g * (i as i64)).to_be_bytes(),
                (uuid + uuid_g * (i as u128)).to_be_bytes(),
            );
            assert!(result.is_ok());
            assert!(result.unwrap());
            assert_eq!(map.size(), 0);
        }

        let result = map.commit();
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(map.size(), 1000);

        let result = map.run_borrow_function(|e164s, uuids| {
            assert_eq!(e164s.len(), 8000);
            assert_eq!(uuids.len(), 16000);
            assert_eq!(set.len(), 1000);
            for i in 0..1000usize {
                let test_number = i64::from_be_bytes(e164s[(8 * i)..(8 * (i + 1))].try_into().unwrap());
                let test_uuid = u128::from_be_bytes(uuids[(16 * i)..(16 * (i + 1))].try_into().unwrap());
                let original_i = ((test_number - number) / number_g) as usize;
                assert_eq!(original_i, ((test_uuid - uuid) / uuid_g) as usize);
                assert!(set.contains(&original_i));
                set.remove(&original_i);
            }
            assert_eq!(set.len(), 0);
            Ok(())
        });
        assert!(result.is_ok());
    }
}
