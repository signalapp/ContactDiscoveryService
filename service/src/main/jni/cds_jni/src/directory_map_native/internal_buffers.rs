// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops::Range;

use byteorder::{BigEndian, ByteOrder};
use thiserror::Error as ThisError;

use crate::{generic_exception, PossibleError};

pub(super) const E164_SIZE_BYTES: usize = 8;
pub(super) const UUID_SIZE_BYTES: usize = 16;

const FREE_E164: [u8; E164_SIZE_BYTES] = [0u8; E164_SIZE_BYTES];
const DELETED_E164: [u8; E164_SIZE_BYTES] = [0xFFu8; E164_SIZE_BYTES];
const FREE_UUID: [u8; UUID_SIZE_BYTES] = [0u8; UUID_SIZE_BYTES];

#[derive(ThisError, Debug, Eq, PartialEq)]
pub(super) enum InternalBuffersError {
    #[error("invalid E164 of {0:?}")]
    InvalidE164([u8; E164_SIZE_BYTES]),
    #[error("buffer is full with {0} elements")]
    BufferFull(usize),
    #[error("our capacity ({0}) does not match rhs capacity ({1})")]
    CapacityMismatch(usize, usize),
}

impl From<InternalBuffersError> for PossibleError {
    fn from(internal_buffers_error: InternalBuffersError) -> Self {
        match internal_buffers_error {
            InternalBuffersError::InvalidE164(_) => {
                generic_exception("java/lang/IllegalArgumentException", &format!("{}", internal_buffers_error))
            }
            InternalBuffersError::BufferFull(_) => {
                generic_exception("java/lang/IllegalStateException", &format!("{}", internal_buffers_error))
            }
            InternalBuffersError::CapacityMismatch(_, _) => {
                generic_exception("java/lang/IllegalStateException", &format!("{}", internal_buffers_error))
            }
        }
    }
}

pub(super) struct InternalBuffers {
    element_count: usize,
    used_slot_count: usize,
    e164s_buffer: Vec<u8>,
    uuids_buffer: Vec<u8>,
}

impl InternalBuffers {
    /// Creates a new internal buffers structure with capacity for the given number of elements.
    ///
    /// In addition to the fixed overhead of the `InternalBuffers` structure itself, also allocates
    /// 24 bytes per element of capacity requested and zero initializes them.
    pub(super) fn new(capacity: usize) -> InternalBuffers {
        let mut result = InternalBuffers {
            element_count: 0,
            used_slot_count: 0,
            e164s_buffer: Vec::with_capacity(capacity * E164_SIZE_BYTES),
            uuids_buffer: Vec::with_capacity(capacity * UUID_SIZE_BYTES),
        };
        result.e164s_buffer.resize(result.e164s_buffer.capacity(), 0);
        result.uuids_buffer.resize(result.uuids_buffer.capacity(), 0);
        result
    }

    pub(super) fn e164s_slice(&self) -> &[u8] {
        self.e164s_buffer.as_slice()
    }

    pub(super) fn uuids_slice(&self) -> &[u8] {
        self.uuids_buffer.as_slice()
    }

    pub(super) fn size(&self) -> usize {
        self.element_count
    }

    pub(super) fn capacity(&self) -> usize {
        self.e164s_buffer.capacity() / E164_SIZE_BYTES
    }

    /// Inserts a mapping from `e164` to `uuid` into the internal buffer.
    ///
    /// Returns `true` if the mapping was added.
    pub(super) fn insert(&mut self, e164: [u8; E164_SIZE_BYTES], uuid: [u8; UUID_SIZE_BYTES]) -> Result<bool, InternalBuffersError> {
        if e164 == DELETED_E164 || e164 == FREE_E164 {
            return Err(InternalBuffersError::InvalidE164(e164));
        }
        let capacity = self.capacity();
        if self.element_count >= capacity {
            return Err(InternalBuffersError::BufferFull(capacity));
        }

        let old_e164 = add_to_buffer(self.e164s_buffer.as_mut_slice(), self.uuids_buffer.as_mut_slice(), e164, uuid);
        let added = old_e164 != e164;
        if old_e164 == FREE_E164 {
            self.used_slot_count += 1;
        }
        if added {
            self.element_count += 1;
        }

        Ok(added)
    }

    /// Removes a mapping from `e164` in the internal buffer.
    ///
    /// Returns `true` if a mapping was removed.
    pub(super) fn remove(&mut self, e164: [u8; E164_SIZE_BYTES]) -> Result<bool, InternalBuffersError> {
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
    /// `self` and `src` must have been created with the same capacity or this will return an `Err`.
    pub(super) fn copy_from(&mut self, src: &Self) -> Result<(), InternalBuffersError> {
        if self.capacity() != src.capacity() {
            return Err(InternalBuffersError::CapacityMismatch(self.capacity(), src.capacity()));
        }
        self.element_count = src.element_count;
        self.used_slot_count = src.used_slot_count;
        self.e164s_buffer.copy_from_slice(src.e164s_buffer.as_slice());
        self.uuids_buffer.copy_from_slice(src.uuids_buffer.as_slice());
        Ok(())
    }
}

fn hash_element(slot_count: usize, e164: [u8; E164_SIZE_BYTES]) -> usize {
    (BigEndian::read_i64(&e164) as usize) % slot_count
}

fn buffer_range(slot_index: usize, element_size: usize) -> Range<usize> {
    (slot_index * element_size)..((slot_index + 1) * element_size)
}

fn e164_buffer_range(slot_index: usize) -> Range<usize> {
    buffer_range(slot_index, E164_SIZE_BYTES)
}

fn uuid_buffer_range(slot_index: usize) -> Range<usize> {
    buffer_range(slot_index, UUID_SIZE_BYTES)
}

/// Adds a mapping from e164 to uuid to the buffers and returns the old key in the assigned slot.
fn add_to_buffer(
    e164s_buffer: &mut [u8],
    uuids_buffer: &mut [u8],
    e164: [u8; E164_SIZE_BYTES],
    uuid: [u8; UUID_SIZE_BYTES],
) -> [u8; E164_SIZE_BYTES] {
    let slot_count = e164s_buffer.len() / E164_SIZE_BYTES;
    if slot_count != uuids_buffer.len() / UUID_SIZE_BYTES {
        panic!("add_to_buffer used incorrectly with mismatching buffer sizes");
    }
    let mut slot_index = hash_element(slot_count, e164);

    // search for a free slot starting at the hash position
    let start_slot_index = slot_index;
    while &e164s_buffer[e164_buffer_range(slot_index)] != &FREE_E164 && &e164s_buffer[e164_buffer_range(slot_index)] != &DELETED_E164 {
        if &e164s_buffer[e164_buffer_range(slot_index)] == &e164 {
            &uuids_buffer[uuid_buffer_range(slot_index)].copy_from_slice(&uuid);
            return e164;
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
    while &e164s_buffer[e164_buffer_range(slot_index)] != &FREE_E164 {
        if &e164s_buffer[e164_buffer_range(slot_index)] == &e164 {
            &uuids_buffer[uuid_buffer_range(slot_index)].copy_from_slice(&uuid);
            return e164;
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
    let mut e164_at_free_slot_index = [0u8; E164_SIZE_BYTES];
    e164_at_free_slot_index.copy_from_slice(&e164s_buffer[e164_buffer_range(free_slot_index)]);
    let e164_at_free_slot_index = e164_at_free_slot_index;

    // insert the new data
    &e164s_buffer[e164_buffer_range(slot_index)].copy_from_slice(&e164);
    &uuids_buffer[uuid_buffer_range(slot_index)].copy_from_slice(&uuid);

    return e164_at_free_slot_index;
}

fn remove_from_buffer(e164s_buffer: &mut [u8], uuids_buffer: &mut [u8], e164: [u8; E164_SIZE_BYTES]) -> bool {
    let slot_count = e164s_buffer.len() / E164_SIZE_BYTES;
    if slot_count != uuids_buffer.len() / UUID_SIZE_BYTES {
        panic!("add_to_buffer used incorrectly with mismatching buffer sizes");
    }
    let mut slot_index = hash_element(slot_count, e164);

    let start_slot_index = slot_index;
    while &e164s_buffer[e164_buffer_range(slot_index)] != &FREE_E164 {
        if &e164s_buffer[e164_buffer_range(slot_index)] == &e164 {
            &e164s_buffer[e164_buffer_range(slot_index)].copy_from_slice(&DELETED_E164);
            &uuids_buffer[uuid_buffer_range(slot_index)].copy_from_slice(&FREE_UUID);
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
        let e164 = [0u8, 0, 0, 0x03, 0x9F, 0x5E, 0x8B, 0x6D];
        let uuid = [
            0xDEu8, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ];

        let mut internal_buffers = InternalBuffers::new(1000);
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
    fn bad_insert() {
        let mut internal_buffers = InternalBuffers::new(1000);

        let result = internal_buffers.insert(FREE_E164, FREE_UUID);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(FREE_E164));

        let result = internal_buffers.insert(DELETED_E164, FREE_UUID);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(DELETED_E164));
    }

    #[test]
    fn bad_remove() {
        let mut internal_buffers = InternalBuffers::new(1000);

        let result = internal_buffers.remove(FREE_E164);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(FREE_E164));

        let result = internal_buffers.remove(DELETED_E164);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::InvalidE164(DELETED_E164));
    }

    #[test]
    fn full() {
        let mut internal_buffers = InternalBuffers::new(1000);

        let number = 15555550100i64;
        let mut e164 = [0u8; E164_SIZE_BYTES];
        let uuid = [42u8; UUID_SIZE_BYTES];
        for i in 0..1000 {
            BigEndian::write_i64(&mut e164, number + (i * 17));
            let result = internal_buffers.insert(e164, uuid);
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
        assert_eq!(internal_buffers.size(), 1000);
        assert_eq!(internal_buffers.used_slot_count, 1000);

        BigEndian::write_i64(&mut e164, number + (1000 * 17));
        let result = internal_buffers.insert(e164, uuid);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalBuffersError::BufferFull(1000));
    }
}
