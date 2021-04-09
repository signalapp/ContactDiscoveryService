// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Mutex, RwLock};

use jni::objects::JClass;
use jni::sys::{jboolean, jfloat, jlong, jobject};
use jni::JNIEnv;

use cds_enclave_ffi::sgxsd::{Phone, SgxsdUuid};
use internal_buffers::InternalBuffers;

use crate::{bool_to_jni_bool, generic_exception, jni_catch, PossibleError, NULL_POINTER_EXCEPTION_CLASS};

mod internal_buffers;

pub(crate) fn convert_native_handle_to_directory_map_reference(native_handle: jlong) -> Result<&'static mut DirectoryMap, PossibleError> {
    if native_handle == 0 {
        Err(generic_exception(NULL_POINTER_EXCEPTION_CLASS, "native_handle is null"))
    } else {
        Ok(unsafe { &mut *(native_handle as *mut DirectoryMap) })
    }
}

struct DirectoryMapBuilding(bool, InternalBuffers);

pub struct DirectoryMap {
    building: Mutex<DirectoryMapBuilding>,
    serving: RwLock<InternalBuffers>,
}

impl DirectoryMap {
    fn new(starting_capacity: usize, min_load_factor: f32, max_load_factor: f32) -> Result<Self, PossibleError> {
        Ok(Self {
            building: Mutex::new(DirectoryMapBuilding(
                false,
                InternalBuffers::new(starting_capacity, min_load_factor, max_load_factor)?,
            )),
            serving: RwLock::new(InternalBuffers::new(starting_capacity, min_load_factor, max_load_factor)?),
        })
    }

    fn insert(&self, e164: Phone, uuid: SgxsdUuid) -> Result<bool, PossibleError> {
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

    fn remove(&self, e164: Phone) -> Result<bool, PossibleError> {
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

    pub(crate) fn borrow_serving_buffers(
        &self,
        borrow: impl FnOnce(&[Phone], &[SgxsdUuid]) -> Result<(), PossibleError>,
    ) -> Result<(), PossibleError> {
        let read_lock = self
            .serving
            .read()
            .expect("DirectoryMap serving read lock poisoned while locking during borrow_serving_buffers");
        borrow(read_lock.e164s_slice(), read_lock.uuids_slice())
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
    starting_capacity: jlong,
    min_load_factor: jfloat,
    max_load_factor: jfloat,
) -> jlong {
    Box::into_raw(Box::new(DirectoryMap::new(
        starting_capacity as usize,
        min_load_factor as f32,
        max_load_factor as f32,
    ))) as jlong
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
        let uuid_high_bits = env.call_method(uuid, "getMostSignificantBits", "()J", &[])?.j().unwrap() as u64;
        let uuid_low_bits = env.call_method(uuid, "getLeastSignificantBits", "()J", &[])?.j().unwrap() as u64;
        Ok(directory_map.insert(
            e164 as Phone,
            SgxsdUuid {
                data64: [uuid_high_bits, uuid_low_bits],
            },
        )?)
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
        Ok(directory_map.remove(e164 as Phone)?)
    }))
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
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn single_element_test() {
        let e164 = 0x000000039F5E8B6D;
        let uuid = SgxsdUuid::from([
            0xDEu8, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ]);

        let map = DirectoryMap::new(1000, 0.75, 0.85).expect("DirectoryMap should construct successfully");
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
        let map = DirectoryMap::new(1000, 0.75, 0.85).expect("DirectoryMap should construct successfully");
        let mut set = HashSet::new();

        let number: u64 = 15555550100;
        let uuid: u128 = 0xd903cd9eab776ff56665988939b4e351;

        let number_g: u64 = 31;
        let uuid_g: u128 = 414094729;

        for i in 0..1000usize {
            set.insert(i);
            let uuid_i = uuid + uuid_g * (i as u128);
            let result = map.insert(
                (number + number_g * (i as u64)) as Phone,
                SgxsdUuid {
                    data64: [(uuid_i >> 64) as u64, uuid_i as u64],
                },
            );
            assert!(result.is_ok());
            assert!(result.unwrap());
            assert_eq!(map.size(), 0);
        }

        let result = map.commit();
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(map.size(), 1000);

        let result = map.borrow_serving_buffers(|e164s, uuids| {
            assert_eq!(e164s.len(), 1284);
            assert_eq!(uuids.len(), 1284);
            assert_eq!(set.len(), 1000);
            for i in 0..1284usize {
                let test_number = e164s[i];
                let test_uuid = ((uuids[i].data64[0] as u128) << 64) | (uuids[i].data64[1] as u128);
                assert_ne!(test_number, 0xFFFFFFFFFFFFFFFF);
                if test_number != 0 {
                    let original_i = ((test_number - number) / number_g) as usize;
                    assert_eq!(original_i, ((test_uuid - uuid) / uuid_g) as usize);
                    assert!(set.contains(&original_i));
                    set.remove(&original_i);
                }
            }
            assert_eq!(set.len(), 0);
            Ok(())
        });
        assert!(result.is_ok());
    }
}
