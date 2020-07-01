//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use alloc::vec::Vec;
use core::marker::*;
use core::num::*;
use core::ptr::*;

use super::bindgen_wrapper::sgx_is_outside_enclave;

pub enum UntrustedSlice<'a> {
    NonEmpty {
        data: NonNull<u8>,
        size: NonZeroUsize,

        _phantom: &'a PhantomData<()>,
    },
    Empty,
}

//
// UntrustedSlice impls
//

impl<'a> UntrustedSlice<'a> {
    pub fn new(p_data: *mut u8, size: usize) -> Result<UntrustedSlice<'static>, ()> {
        let maybe_data_and_size = if let Some(size) = NonZeroUsize::new(size) {
            if let Some(data) = NonNull::new(p_data) {
                Some((data, size))
            } else {
                None
            }
        } else {
            None
        };
        if let Some((data, size)) = maybe_data_and_size {
            if unsafe { sgx_is_outside_enclave(data.as_ptr() as *const libc::c_void, size.get()) } != 1 {
                return Err(());
            }
            if data.as_ptr().wrapping_add(size.get()) < data.as_ptr() {
                return Err(());
            }
            Ok(UntrustedSlice::NonEmpty {
                data,
                size,
                _phantom: &PhantomData,
            })
        } else {
            Ok(UntrustedSlice::Empty)
        }
    }

    pub fn len(&self) -> usize {
        match self {
            UntrustedSlice::NonEmpty { size, .. } => size.get(),
            UntrustedSlice::Empty => 0,
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        match self {
            Self::NonEmpty { data, .. } => data.as_ptr(),
            Self::Empty => null(),
        }
    }

    pub fn offset(&self, offset: usize) -> UntrustedSlice<'_> {
        match self {
            UntrustedSlice::NonEmpty { data, size, _phantom } => {
                if let Some(size) = size.get().checked_sub(offset) {
                    if let Some(size) = NonZeroUsize::new(size) {
                        let data = unsafe { NonNull::new_unchecked(data.as_ptr().add(offset)) };
                        UntrustedSlice::NonEmpty {
                            data,
                            size,
                            _phantom: &PhantomData,
                        }
                    } else {
                        UntrustedSlice::Empty
                    }
                } else {
                    UntrustedSlice::Empty
                }
            }
            UntrustedSlice::Empty => UntrustedSlice::Empty,
        }
    }

    pub fn read_bytes(&self, read_count: usize) -> Result<Vec<u8>, ()> {
        match self {
            UntrustedSlice::NonEmpty { data, size, _phantom } => {
                if read_count <= size.get() {
                    let mut dest = Vec::with_capacity(read_count);
                    unsafe {
                        data.as_ptr().copy_to_nonoverlapping(dest.as_mut_ptr(), read_count);
                        dest.set_len(read_count);
                    };
                    Ok(dest)
                } else {
                    Err(())
                }
            }
            UntrustedSlice::Empty => {
                if read_count == 0 {
                    Ok(Vec::new())
                } else {
                    Err(())
                }
            }
        }
    }

    pub fn write_bytes(&self, write_bytes: &[u8]) -> Result<(), ()> {
        match self {
            UntrustedSlice::NonEmpty { data, size, _phantom } => {
                if write_bytes.len() <= size.get() {
                    unsafe {
                        write_bytes.as_ptr().copy_to(data.as_ptr(), write_bytes.len());
                    }
                    Ok(())
                } else {
                    Err(())
                }
            }
            UntrustedSlice::Empty => {
                if write_bytes.is_empty() {
                    Ok(())
                } else {
                    Err(())
                }
            }
        }
    }
}

impl<'a> Default for UntrustedSlice<'a> {
    fn default() -> Self {
        UntrustedSlice::Empty
    }
}

#[cfg(test)]
mod test {
    use mockers::*;
    use test_ffi::rand_bytes;

    use super::super::mocks;
    use super::*;

    struct TestVec {
        ptr:  *mut u8,
        size: usize,
    }
    impl TestVec {
        fn new(size: usize) -> Self {
            let mut data_vec: Vec<u8> = rand_bytes(vec![0; size]);
            let ptr: *mut u8 = data_vec.as_mut_ptr();
            let size: usize = data_vec.capacity();
            std::mem::forget(data_vec);
            Self { ptr, size }
        }
    }
    impl Drop for TestVec {
        fn drop(&mut self) {
            unsafe { Vec::from_raw_parts(self.ptr, self.size, self.size) };
        }
    }

    #[test]
    fn test_new_valid_empty() {
        assert_eq!(UntrustedSlice::new(std::ptr::null_mut(), 0).unwrap().len(), 0);
        assert_eq!(UntrustedSlice::new(std::ptr::null_mut(), 1).unwrap().len(), 0);
        assert_eq!(UntrustedSlice::new(std::ptr::null_mut(), usize::max_value()).unwrap().len(), 0);
        assert_eq!(UntrustedSlice::new(std::ptr::NonNull::dangling().as_ptr(), 0).unwrap().len(), 0);
    }

    #[test]
    fn test_new_invalid() {
        let scenario = Scenario::new();
        let test_vec = TestVec::new(1);

        mocks::expect_sgx_is_outside_enclave(&scenario, test_vec.ptr as *const libc::c_void, usize::max_value(), true);
        assert!(UntrustedSlice::new(test_vec.ptr, usize::max_value()).is_err());

        mocks::expect_sgx_is_outside_enclave(&scenario, test_vec.ptr as *const libc::c_void, test_vec.size, false);
        assert!(UntrustedSlice::new(test_vec.ptr, test_vec.size).is_err());
    }

    #[test]
    fn test_offset() {
        let scenario = Scenario::new();
        let test_vec = TestVec::new(10);

        mocks::expect_sgx_is_outside_enclave(&scenario, test_vec.ptr as *const libc::c_void, test_vec.size, true);
        let untrusted = UntrustedSlice::new(test_vec.ptr, test_vec.size).unwrap();

        assert_eq!(untrusted.len(), test_vec.size);

        for offset in 0..test_vec.size {
            assert_eq!(untrusted.offset(offset).len(), test_vec.size - offset);
        }

        assert_eq!(untrusted.offset(test_vec.size + 1).len(), 0);
        assert_eq!(untrusted.offset(usize::max_value()).len(), 0);
    }

    #[test]
    fn test_read_write_bytes() {
        let scenario = Scenario::new();
        let test_vec = TestVec::new(10);

        mocks::expect_sgx_is_outside_enclave(&scenario, test_vec.ptr as *const libc::c_void, test_vec.size, true);
        let untrusted = UntrustedSlice::new(test_vec.ptr, test_vec.size).unwrap();

        let write_data = rand_bytes(vec![0; test_vec.size]);
        assert!(untrusted.write_bytes(&write_data).is_ok());
        assert_eq!(&untrusted.read_bytes(test_vec.size).unwrap(), &write_data);

        for offset in 0..test_vec.size {
            for length in 0..=(test_vec.size - offset) {
                let write_data = rand_bytes(vec![0; length]);
                assert!(untrusted.offset(offset).write_bytes(&write_data).is_ok());
                assert_eq!(&untrusted.offset(offset).read_bytes(length).unwrap(), &write_data);
            }
            assert!(untrusted.offset(offset).write_bytes(&vec![0; test_vec.size - offset + 1]).is_err());
            assert!(untrusted.offset(offset).read_bytes(test_vec.size - offset + 1).is_err());
            assert!(untrusted.offset(offset).read_bytes(usize::max_value()).is_err());
        }

        assert!(untrusted.offset(test_vec.size).write_bytes(&[]).is_ok());
        assert!(untrusted.offset(test_vec.size).read_bytes(0).unwrap().is_empty());
        assert!(untrusted.offset(test_vec.size + 1).write_bytes(&[]).is_ok());
        assert!(untrusted.offset(test_vec.size + 1).read_bytes(0).unwrap().is_empty());
        assert!(untrusted.offset(usize::max_value()).write_bytes(&[]).is_ok());
        assert!(untrusted.offset(usize::max_value()).read_bytes(0).unwrap().is_empty());

        assert!(untrusted.offset(test_vec.size).read_bytes(1).is_err());
        assert!(untrusted.offset(test_vec.size).write_bytes(&[0]).is_err());
        assert!(untrusted.offset(test_vec.size).read_bytes(usize::max_value()).is_err());
        assert!(untrusted.offset(usize::max_value()).read_bytes(1).is_err());
        assert!(untrusted.offset(usize::max_value()).write_bytes(&[0]).is_err());
        assert!(untrusted.offset(usize::max_value()).read_bytes(usize::max_value()).is_err());
    }
}
