// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::max;

use thiserror::Error as ThisError;

use cds_enclave_ffi::sgxsd::{Phone, SgxsdUuid};

use crate::directory_map_native;
use crate::{generic_exception, PossibleError};
use std::io::{Read, Write};

const FREE_E164: Phone = 0;
const DELETED_E164: Phone = 0xFFFFFFFFFFFFFFFF;
const FREE_UUID: SgxsdUuid = SgxsdUuid { data64: [0, 0] };

#[derive(ThisError, Debug)]
pub(super) enum InternalBuffersError {
    #[error("invalid E164 of {0}")]
    InvalidE164(Phone),
    #[error("buffer is full with {0} elements and {1} capacity")]
    BufferFull(usize, usize),
    #[error("invalid minimum load factor ({0}) must be in range [0, 1]")]
    InvalidMinimumLoadFactor(f32),
    #[error("invalid maximum load factor ({0}) must be in range [0, 1]")]
    InvalidMaximumLoadFactor(f32),
    #[error("invalid load factors; minimum must not equal or exceed maximum ({0}, {0})")]
    InvalidLoadFactorTuple(f32, f32),
    #[error("io error inside internal buffers ({0})")]
    IoError(#[from] std::io::Error),
}

impl PartialEq for InternalBuffersError {
    fn eq(&self, other: &Self) -> bool {
        use InternalBuffersError::*;
        match (self, other) {
            (&InvalidE164(ref a), &InvalidE164(ref b)) => a == b,
            (&BufferFull(ref a, ref b), &BufferFull(ref c, ref d)) => a == c && b == d,
            (&InvalidMinimumLoadFactor(ref a), &InvalidMinimumLoadFactor(ref b)) => a == b,
            (&InvalidMaximumLoadFactor(ref a), &InvalidMaximumLoadFactor(ref b)) => a == b,
            (&InvalidLoadFactorTuple(ref a, ref b), &InvalidLoadFactorTuple(ref c, ref d)) => a == c && b == d,
            (&IoError(ref a), &IoError(ref b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

impl From<InternalBuffersError> for PossibleError {
    fn from(internal_buffers_error: InternalBuffersError) -> Self {
        match internal_buffers_error {
            InternalBuffersError::IoError(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                generic_exception("java/io/EOFException", &format!("{}", internal_buffers_error))
            }
            InternalBuffersError::IoError(error) if error.kind() == std::io::ErrorKind::Other && is_jni_ioerror(&error) => {
                PossibleError::AlreadyThrown(get_jni_error_from_ioerror(error))
            }
            InternalBuffersError::IoError(_) => generic_exception("java/io/IOException", &format!("{}", internal_buffers_error)),
            InternalBuffersError::InvalidE164(_)
            | InternalBuffersError::InvalidMinimumLoadFactor(_)
            | InternalBuffersError::InvalidMaximumLoadFactor(_)
            | InternalBuffersError::InvalidLoadFactorTuple(_, _) => {
                generic_exception("java/lang/IllegalArgumentException", &format!("{}", internal_buffers_error))
            }
            InternalBuffersError::BufferFull(_, _) => {
                generic_exception("java/lang/IllegalStateException", &format!("{}", internal_buffers_error))
            }
        }
    }
}

fn get_jni_error_from_ioerror(ioerror: std::io::Error) -> jni::errors::Error {
    if let Some(e) = ioerror.into_inner() {
        if let Ok(ie) = e.downcast::<directory_map_native::io::IoError>() {
            match *ie {
                directory_map_native::io::IoError::JniError(je) => return je,
                _ => panic!("unguarded call to get_jni_error_from_ioerror"),
            }
        }
    }
    panic!("unguarded call to get_jni_error_from_ioerror")
}

fn is_jni_ioerror(ioerror: &std::io::Error) -> bool {
    if let Some(e) = ioerror.get_ref() {
        if let Some(ie) = e.downcast_ref::<directory_map_native::io::IoError>() {
            return match ie {
                directory_map_native::io::IoError::JniError(_) => true,
                _ => false,
            };
        }
    }
    false
}

pub(super) struct InternalBuffers {
    min_load_factor: f32,
    max_load_factor: f32,
    element_count: usize,
    used_slot_count: usize,
    e164s_buffer: Vec<Phone>,
    uuids_buffer: Vec<SgxsdUuid>,
}

impl InternalBuffers {
    /// Creates a new internal buffers structure with capacity for the given number of elements.
    ///
    /// In addition to the fixed overhead of the `InternalBuffers` structure itself, also allocates
    /// 24 bytes per element of capacity requested and zero initializes them.
    pub(super) fn new(capacity: usize, min_load_factor: f32, max_load_factor: f32) -> Result<InternalBuffers, InternalBuffersError> {
        if min_load_factor > 1.0 || min_load_factor < 0.0 {
            return Err(InternalBuffersError::InvalidMinimumLoadFactor(min_load_factor));
        }
        if max_load_factor > 1.0 || max_load_factor < 0.0 {
            return Err(InternalBuffersError::InvalidMaximumLoadFactor(max_load_factor));
        }
        if min_load_factor >= max_load_factor {
            return Err(InternalBuffersError::InvalidLoadFactorTuple(min_load_factor, max_load_factor));
        }
        let mut result = InternalBuffers {
            min_load_factor,
            max_load_factor,
            element_count: 0,
            used_slot_count: 0,
            e164s_buffer: Vec::with_capacity(capacity),
            uuids_buffer: Vec::with_capacity(capacity),
        };
        result.e164s_buffer.resize(result.e164s_buffer.capacity(), FREE_E164);
        result.uuids_buffer.resize(result.uuids_buffer.capacity(), FREE_UUID);
        Ok(result)
    }

    pub(super) fn e164s_slice(&self) -> &[Phone] {
        self.e164s_buffer.as_slice()
    }

    pub(super) fn uuids_slice(&self) -> &[SgxsdUuid] {
        self.uuids_buffer.as_slice()
    }

    pub(super) fn size(&self) -> usize {
        self.element_count
    }

    pub(super) fn capacity(&self) -> usize {
        // it is our intention throughout that len==capacity for each buffer and that the two
        // buffer's capacities match
        //
        // however, this is not enforceable using reserve_exact as, despite the name, you are not
        // guaranteed to get exactly the intended amount of capacity; this could result in the two
        // buffers having non-matching capacity; additionally this could result in both being longer
        // than the desired length
        //
        // we can control the length exactly though, so we will return length here as that can be
        // guaranteed to be equivalent between the two buffers and we will treat the part of the
        // Vec between len and capacity as non-existent for the purpose of the 'capacity' of the
        // combined internal buffer
        self.e164s_buffer.len()
    }

    /// Inserts a mapping from `e164` to `uuid` into the internal buffer.
    ///
    /// Returns `true` if the mapping was added.
    pub(super) fn insert(&mut self, e164: Phone, uuid: SgxsdUuid) -> Result<bool, InternalBuffersError> {
        if e164 == DELETED_E164 || e164 == FREE_E164 {
            return Err(InternalBuffersError::InvalidE164(e164));
        }
        let capacity = self.capacity();
        if self.element_count == capacity {
            self.rehash();
        }
        if self.element_count > capacity {
            return Err(InternalBuffersError::BufferFull(self.element_count, capacity));
        }

        let old_e164 = add_to_buffer(self.e164s_buffer.as_mut_slice(), self.uuids_buffer.as_mut_slice(), e164, uuid, true);
        let added = old_e164 != e164;
        if old_e164 == FREE_E164 {
            self.used_slot_count += 1;
        }
        if added {
            self.element_count += 1;
        }
        let max_load_factor_slot_count: usize = (self.capacity() as f64 * self.max_load_factor as f64) as usize;
        if self.used_slot_count >= max_load_factor_slot_count {
            self.rehash();
        }

        Ok(added)
    }

    /// Removes a mapping from `e164` in the internal buffer.
    ///
    /// Returns `true` if a mapping was removed.
    pub(super) fn remove(&mut self, e164: Phone) -> Result<bool, InternalBuffersError> {
        if e164 == DELETED_E164 || e164 == FREE_E164 {
            return Err(InternalBuffersError::InvalidE164(e164));
        }
        let removed = remove_from_buffer(self.e164s_buffer.as_mut_slice(), self.uuids_buffer.as_mut_slice(), e164);
        if removed {
            self.element_count -= 1;
        }
        Ok(removed)
    }

    /// Copies every field from the `src` internal buffer.
    ///
    /// Increases the size of `self`'s buffers to have enough space for `src`'s elements and then
    /// performs a deep copy.
    pub(super) fn copy_from(&mut self, src: &Self) -> Result<(), InternalBuffersError> {
        let src_capacity = src.capacity();
        let self_capacity = self.capacity();
        if self_capacity < src_capacity {
            // resize alone might increase the space far more than we want, so let's manually
            // reserve exactly the amount of space we want
            self.e164s_buffer.reserve_exact(src_capacity - self_capacity);
            self.uuids_buffer.reserve_exact(src_capacity - self_capacity);
        }
        if self_capacity != src_capacity {
            self.e164s_buffer.resize(src_capacity, FREE_E164);
            self.uuids_buffer.resize(src_capacity, FREE_UUID);
        }
        self.min_load_factor = src.min_load_factor;
        self.max_load_factor = src.max_load_factor;
        self.element_count = src.element_count;
        self.used_slot_count = src.used_slot_count;
        self.e164s_buffer.copy_from_slice(src.e164s_buffer.as_slice());
        self.uuids_buffer.copy_from_slice(src.uuids_buffer.as_slice());
        Ok(())
    }

    /// Reads from the given `Read` implementation to overwrite the state of this buffer. All local
    /// state will be overwritten.
    pub(super) fn read_from(&mut self, read: &mut impl Read) -> Result<(), InternalBuffersError> {
        let mut buf4 = [0u8; 4];
        read.read_exact(&mut buf4)?;
        let capacity = u32::from_be_bytes(buf4) as usize;
        read.read_exact(&mut buf4)?;
        let element_count = u32::from_be_bytes(buf4) as usize;
        read.read_exact(&mut buf4)?;
        let used_slot_count = u32::from_be_bytes(buf4) as usize;
        self.clear_to_capacity(capacity);
        self.element_count = element_count;
        self.used_slot_count = used_slot_count;
        let e164_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(self.e164s_buffer.as_ptr() as *mut u8, capacity * std::mem::size_of::<Phone>()) };
        let uuid_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(self.uuids_buffer.as_ptr() as *mut u8, capacity * std::mem::size_of::<SgxsdUuid>()) };
        read.read_exact(e164_byte_slice)?;
        read.read_exact(uuid_byte_slice)?;
        Ok(())
    }

    /// Writes the state of this buffer to the given `Write` implementation.
    pub(super) fn write_to(&self, write: &mut impl Write) -> Result<(), InternalBuffersError> {
        let capacity = self.capacity();
        write.write_all(&(capacity as u32).to_be_bytes())?;
        write.write_all(&(self.element_count as u32).to_be_bytes())?;
        write.write_all(&(self.used_slot_count as u32).to_be_bytes())?;
        let e164_byte_slice =
            unsafe { std::slice::from_raw_parts(self.e164s_buffer.as_ptr() as *const u8, capacity * std::mem::size_of::<Phone>()) };
        let uuid_byte_slice =
            unsafe { std::slice::from_raw_parts(self.uuids_buffer.as_ptr() as *const u8, capacity * std::mem::size_of::<SgxsdUuid>()) };
        write.write_all(e164_byte_slice)?;
        write.write_all(uuid_byte_slice)?;
        Ok(())
    }

    fn rehash(&mut self) {
        let new_slot_count: usize = max((self.element_count as f64 / self.min_load_factor as f64) as usize, self.capacity());
        let mut new_e164s_buffer = Vec::<Phone>::with_capacity(new_slot_count);
        let mut new_uuids_buffer = Vec::<SgxsdUuid>::with_capacity(new_slot_count);
        new_e164s_buffer.resize(new_slot_count, FREE_E164);
        new_uuids_buffer.resize(new_slot_count, FREE_UUID);
        let mut new_used_slot_count = 0usize;

        for i in 0..self.capacity() {
            let e164: Phone = u64::from_be(self.e164s_buffer[i]);
            if e164 != FREE_E164 && e164 != DELETED_E164 {
                let new_buffer_old_e164 = add_to_buffer(
                    new_e164s_buffer.as_mut_slice(),
                    new_uuids_buffer.as_mut_slice(),
                    e164,
                    self.uuids_buffer[i],
                    false,
                );
                if new_buffer_old_e164 == FREE_E164 {
                    new_used_slot_count += 1;
                }
            }
        }
        self.e164s_buffer = new_e164s_buffer;
        self.uuids_buffer = new_uuids_buffer;
        self.used_slot_count = new_used_slot_count;
    }

    /// Clears the internal buffer state and allocates free storage space for `capacity` elements
    /// in the resulting state.
    fn clear_to_capacity(&mut self, capacity: usize) {
        self.e164s_buffer.truncate(0);
        self.uuids_buffer.truncate(0);
        // this is not efficient given we're about to overwrite all this memory, but don't
        // really need the unsafe version at the moment
        self.e164s_buffer.resize(capacity, FREE_E164);
        self.uuids_buffer.resize(capacity, FREE_UUID);
    }

    #[cfg(test)]
    fn get(&self, e164: Phone) -> Option<SgxsdUuid> {
        let e164: Phone = (e164 as u64).to_be();

        self.e164s_buffer
            .iter()
            .zip(self.uuids_buffer.iter())
            .find_map(|(candidate_e164, uuid)| {
                if candidate_e164 == &e164 {
                    Some(SgxsdUuid {
                        data64: [u64::from_be(uuid.data64[0]), u64::from_be(uuid.data64[1])],
                    })
                } else {
                    None
                }
            })
    }
}

fn hash_element(slot_count: usize, e164: Phone) -> usize {
    (e164 as usize) % slot_count
}

/// Adds a mapping from e164 to uuid to the buffers and returns the old key in the assigned slot.
fn add_to_buffer(e164s_buffer: &mut [Phone], uuids_buffer: &mut [SgxsdUuid], e164: Phone, uuid: SgxsdUuid, convert_uuid: bool) -> Phone {
    let slot_count = e164s_buffer.len();
    if slot_count != uuids_buffer.len() {
        panic!("add_to_buffer used incorrectly with mismatching buffer sizes");
    }
    let mut slot_index = hash_element(slot_count, e164);

    let e164: Phone = (e164 as u64).to_be();
    let uuid = if convert_uuid {
        SgxsdUuid {
            data64: [uuid.data64[0].to_be(), uuid.data64[1].to_be()],
        }
    } else {
        uuid
    };

    // search for a free slot starting at the hash position
    let start_slot_index = slot_index;
    while e164s_buffer[slot_index] != FREE_E164 && e164s_buffer[slot_index] != DELETED_E164 {
        if e164s_buffer[slot_index] == e164 {
            uuids_buffer[slot_index] = uuid;
            return u64::from_be(e164);
        }
        slot_index += 1;
        if slot_index == slot_count {
            slot_index = 0;
        }
        if slot_index == start_slot_index {
            panic!("add_to_buffer used incorrectly with an already full buffer");
        }
    }

    // we found the first free slot after the hash entrypoint
    // but we still need to check if it's in any of the following buckets
    let free_slot_index = slot_index;
    while e164s_buffer[slot_index] != FREE_E164 {
        if e164s_buffer[slot_index] == e164 {
            uuids_buffer[slot_index] = uuid;
            return u64::from_be(e164);
        }
        slot_index += 1;
        if slot_index == slot_count {
            slot_index = 0;
        }
        if slot_index == free_slot_index {
            break;
        }
    }

    // if we get here it's not in the table anywhere, so now we need to actually write into the free
    // slot we found earlier

    // copy the old key
    let e164_at_free_slot_index = e164s_buffer[free_slot_index];

    // insert the new data
    e164s_buffer[free_slot_index] = e164;
    uuids_buffer[free_slot_index] = uuid;

    return u64::from_be(e164_at_free_slot_index);
}

fn remove_from_buffer(e164s_buffer: &mut [Phone], uuids_buffer: &mut [SgxsdUuid], e164: Phone) -> bool {
    let slot_count = e164s_buffer.len();
    if slot_count != uuids_buffer.len() {
        panic!("remove_from_buffer used incorrectly with mismatching buffer sizes");
    }
    let mut slot_index = hash_element(slot_count, e164);
    let e164: Phone = (e164 as u64).to_be();

    let start_slot_index = slot_index;
    while e164s_buffer[slot_index] != FREE_E164 {
        if e164s_buffer[slot_index] == e164 {
            e164s_buffer[slot_index] = DELETED_E164;
            uuids_buffer[slot_index] = FREE_UUID;
            return true;
        }
        slot_index += 1;
        if slot_index == slot_count {
            slot_index = 0;
        }
        if slot_index == start_slot_index {
            return false;
        }
    }
    return false;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn single_element_test() {
        let e164: Phone = 0x000000039F5E8B6D;
        let uuid = SgxsdUuid::from([
            0xDEu8, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ]);

        let mut internal_buffers = InternalBuffers::new(1000, 0.75, 0.85).expect("InternalBuffers should construct successfully");
        assert_eq!(internal_buffers.capacity(), 1000);
        assert_eq!(internal_buffers.size(), 0);
        assert_eq!(internal_buffers.used_slot_count, 0);

        let result = internal_buffers.insert(e164, uuid);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(internal_buffers.capacity(), 1000);
        assert_eq!(internal_buffers.size(), 1);
        assert_eq!(internal_buffers.used_slot_count, 1);

        let result = internal_buffers.insert(e164, uuid);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(internal_buffers.capacity(), 1000);
        assert_eq!(internal_buffers.size(), 1);
        assert_eq!(internal_buffers.used_slot_count, 1);

        let result = internal_buffers.remove(e164);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(internal_buffers.capacity(), 1000);
        assert_eq!(internal_buffers.size(), 0);
        assert_eq!(internal_buffers.used_slot_count, 1);

        let result = internal_buffers.remove(e164);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(internal_buffers.capacity(), 1000);
        assert_eq!(internal_buffers.size(), 0);
        assert_eq!(internal_buffers.used_slot_count, 1);
    }

    #[test]
    fn replace() {
        let e164: Phone = 0x000000039F5E8B6D;
        let original_uuid = SgxsdUuid::from([
            0xDEu8, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ]);

        let changed_uuid = SgxsdUuid::from([
            0xFEu8, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ]);

        let mut internal_buffers = InternalBuffers::new(1000, 0.75, 0.85).expect("InternalBuffers should construct successfully");

        let result = internal_buffers.insert(e164, original_uuid);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(internal_buffers.capacity(), 1000);
        assert_eq!(internal_buffers.size(), 1);
        assert_eq!(internal_buffers.used_slot_count, 1);
        assert!(internal_buffers.get(e164).is_some());

        if let Some(uuid) = internal_buffers.get(e164) {
            assert_eq!(original_uuid.data64, uuid.data64);
        }

        let result = internal_buffers.insert(e164, changed_uuid);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(internal_buffers.capacity(), 1000);
        assert_eq!(internal_buffers.size(), 1);
        assert_eq!(internal_buffers.used_slot_count, 1);
        assert!(internal_buffers.get(e164).is_some());

        if let Some(uuid) = internal_buffers.get(e164) {
            assert_eq!(changed_uuid.data64, uuid.data64);
        }
    }

    #[test]
    fn bad_insert() {
        let mut internal_buffers = InternalBuffers::new(1000, 0.75, 0.85).expect("InternalBuffers should construct successfully");

        let result = internal_buffers.insert(FREE_E164, FREE_UUID);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(FREE_E164));

        let result = internal_buffers.insert(DELETED_E164, FREE_UUID);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(DELETED_E164));
    }

    #[test]
    fn bad_remove() {
        let mut internal_buffers = InternalBuffers::new(1000, 0.75, 0.85).expect("InternalBuffers should construct successfully");

        let result = internal_buffers.remove(FREE_E164);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(FREE_E164));

        let result = internal_buffers.remove(DELETED_E164);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(DELETED_E164));
    }

    #[test]
    fn rehash() {
        let mut internal_buffers = InternalBuffers::new(1000, 0.75, 0.85).expect("InternalBuffers should construct successfully");
        assert_eq!(internal_buffers.capacity(), 1000);

        let e164: Phone = 1_555_555_0100;
        let uuid = SgxsdUuid::from([42u8; 16]);
        for i in 0..1000 {
            let result = internal_buffers.insert(e164 + i * 17, uuid);
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
        assert_eq!(internal_buffers.size(), 1000);
        assert_eq!(internal_buffers.used_slot_count, 1000);
        assert_eq!(internal_buffers.capacity(), 1284);

        let result = internal_buffers.insert(e164 + 1000 * 17, uuid);
        assert!(result.is_ok());
        assert_eq!(internal_buffers.size(), 1001);
        assert_eq!(internal_buffers.used_slot_count, 1001);
        assert_eq!(internal_buffers.capacity(), 1284);
    }

    #[test]
    fn fill_in_the_gaps() {
        let mut internal_buffers = InternalBuffers::new(1000, 0.75, 0.85).expect("InternalBuffers should construct successfully");
        let mut phone = [500, 1500, 2500, 3500];
        let mut uuid = [
            SgxsdUuid::from([0x80; 16]),
            SgxsdUuid::from([0x81; 16]),
            SgxsdUuid::from([0x82; 16]),
            SgxsdUuid::from([0x83; 16]),
        ];

        assert_eq!(phone.len(), uuid.len());
        assert!(phone.len() >= 3);
        let capacity = internal_buffers.capacity();
        let hash = hash_element(capacity, phone[0]);
        let mut inserts_done: usize = 0;
        for i in 0..phone.len() - 1 {
            assert_eq!(capacity, internal_buffers.capacity());
            let new_hash = hash_element(capacity, phone[i]);
            assert_eq!(hash, new_hash);
            internal_buffers.insert(phone[i], uuid[i]).expect("insert should succeed");
            inserts_done += 1;
            assert_eq!(internal_buffers.used_slot_count, inserts_done);
        }
        internal_buffers.remove(phone[phone.len() - 3]).expect("remove should succeed");
        assert_eq!(internal_buffers.used_slot_count, inserts_done);
        assert_eq!(internal_buffers.element_count, inserts_done - 1);
        internal_buffers
            .insert(phone[phone.len() - 1], uuid[uuid.len() - 1])
            .expect("insert should succeed");
        inserts_done += 1;
        assert_eq!(internal_buffers.used_slot_count, inserts_done - 1);
        assert_eq!(internal_buffers.element_count, inserts_done - 1);

        // the order in the table should now be 0 -> 3 -> 2 because we inserted the first three,
        // then removed the second one, then added the fourth.
        assert!(capacity > hash + inserts_done - 1);
        let len = phone.len();
        let tmp = phone[len - 3];
        phone[len - 3] = phone[len - 1];
        phone[len - 1] = tmp;
        let len = uuid.len();
        let tmp = uuid[len - 3];
        uuid[len - 3] = uuid[len - 1];
        uuid[len - 1] = tmp;
        for i in hash..hash + inserts_done - 1 {
            assert_eq!(internal_buffers.e164s_buffer[i], phone[i - hash].to_be());
            let test_uuid = [uuid[i - hash].data64[0].to_be(), uuid[i - hash].data64[1].to_be()];
            assert_eq!(internal_buffers.uuids_buffer[i].data64, test_uuid);
        }
        for i in 0..internal_buffers.e164s_buffer.len() {
            assert_ne!(internal_buffers.e164s_buffer[i], DELETED_E164);
        }
    }
}
