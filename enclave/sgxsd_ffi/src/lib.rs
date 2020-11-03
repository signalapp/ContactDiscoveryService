//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![cfg_attr(not(any(test, feature = "test")), no_std)]
#![allow(unused_parens, clippy::style, clippy::large_enum_variant)]
#![warn(
    bare_trait_objects,
    elided_lifetimes_in_paths,
    trivial_numeric_casts,
    variant_size_differences,
    clippy::integer_arithmetic
)]
#![deny(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::expl_impl_clone_on_copy,
    clippy::explicit_into_iter_loop,
    clippy::explicit_iter_loop,
    clippy::float_arithmetic,
    clippy::float_cmp_const,
    clippy::indexing_slicing,
    clippy::maybe_infinite_iter,
    clippy::mem_forget,
    clippy::missing_const_for_fn,
    clippy::multiple_inherent_impl,
    clippy::mut_mut,
    clippy::needless_borrow,
    clippy::option_unwrap_used,
    clippy::panicking_unwrap,
    clippy::print_stdout,
    clippy::redundant_clone,
    clippy::replace_consts,
    clippy::result_unwrap_used,
    clippy::shadow_unrelated,
    clippy::unimplemented,
    clippy::use_debug,
    clippy::use_self,
    clippy::use_underscore_binding,
    clippy::wildcard_enum_match_arm
)]

extern crate alloc;

#[rustfmt::skip]
#[rustfmt::skip::attributes(allow)]
#[allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    improper_ctypes,
    clippy::all,
    clippy::pedantic,
    clippy::integer_arithmetic
)]
mod bindgen_wrapper;
pub mod ecalls;

#[cfg(any(test, feature = "test"))]
pub mod mocks;

use core::ffi::c_void;
use core::num;
use core::ptr;
use core::sync;

use num_traits::ToPrimitive;
use rand_core::{CryptoRng, RngCore};
use sgx_ffi::util::{clear, SecretValue};

use crate::bindgen_wrapper::{br_hmac_context, br_hmac_init, br_hmac_update, br_hmac_out, br_hmac_key_context, br_sha224_update, br_sha256_SIZE, br_sha256_context, br_sha256_init, br_sha256_out, curve25519_donna, sgx_status_t as SgxStatus, sgxsd_aes_gcm_decrypt, sgxsd_aes_gcm_encrypt, sgxsd_enclave_read_rand, sgxsd_rand_buf, SGX_ERROR_INVALID_PARAMETER, SGX_SUCCESS, br_hmac_key_init};

//
// public API
//

pub struct RdRand;

pub struct AesGcmKey {
    key: SecretValue<sgxsd_aes_gcm_key>,
}

pub use bindgen_wrapper::sgxsd_aes_gcm_key;

pub use bindgen_wrapper::sgxsd_aes_gcm_iv;
pub type AesGcmIv = sgxsd_aes_gcm_iv;

pub use bindgen_wrapper::sgxsd_aes_gcm_mac;
pub type AesGcmMac = sgxsd_aes_gcm_mac;

pub struct SHA256Context {
    context: br_sha256_context,
}

pub struct Curve25519Key {
    privkey: SecretValue<[u8; 32]>,
    pubkey:  [u8; 32],
}

//
// RdRand impls
//

impl CryptoRng for RdRand {}
impl RngCore for RdRand {
    fn next_u32(&mut self) -> u32 {
        let random_bytes = self.rand_bytes([0; 4]);
        u32::from_ne_bytes(random_bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let random_bytes = self.rand_bytes([0; 8]);
        u64::from_ne_bytes(random_bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        while let Err(_) = self.try_fill_bytes(dest) {
            sync::atomic::spin_loop_hint();
        }
    }

    fn try_fill_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let mut rand_buf = sgxsd_rand_buf::default();
        while !dest.is_empty() {
            match num::NonZeroU32::new(unsafe { sgxsd_enclave_read_rand(&mut rand_buf) }) {
                None => (),
                Some(error) => {
                    clear(&mut rand_buf.x);
                    return Err(error.into());
                }
            }
            let dest_part_len = rand_buf.x.len().min(dest.len());
            let (dest_part, dest_rest) = dest.split_at_mut(dest_part_len);
            dest_part.copy_from_slice(rand_buf.x.get(..dest_part_len).unwrap_or_else(|| unreachable!()));
            dest = dest_rest;
        }
        clear(&mut rand_buf.x);
        Ok(())
    }
}
impl RdRand {
    pub fn rand_bytes<T>(&mut self, mut buf: T) -> T
    where T: AsMut<[u8]> {
        self.fill_bytes(buf.as_mut());
        buf
    }
}

//
// sgxsd_aes_gcm_key impls
//

impl AsRef<[u8]> for sgxsd_aes_gcm_key {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for sgxsd_aes_gcm_key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

//
// AesGcmKey impls
//

impl Default for AesGcmKey {
    fn default() -> Self {
        let mut new_self = Self { key: Default::default() };
        RdRand.fill_bytes(&mut new_self.key.get_mut().data);
        new_self
    }
}

impl AesGcmKey {
    pub fn new(data: &[u8]) -> Result<Self, SgxStatus> {
        let mut new = Self { key: Default::default() };
        if data.len() != new.key.get().data.len() {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
        new.key.get_mut().data.copy_from_slice(data);
        Ok(new)
    }

    pub fn set_key(&mut self, data: &[u8; 32]) {
        self.key.get_mut().data = *data;
    }

    pub fn decrypt(&self, data: &mut [u8], aad: &[u8], iv: &AesGcmIv, mac: &AesGcmMac) -> Result<(), SgxStatus> {
        let data_len = data.len().to_u32().ok_or(SGX_ERROR_INVALID_PARAMETER)?;
        let aad_len = aad.len().to_u32().ok_or(SGX_ERROR_INVALID_PARAMETER)?;

        match unsafe {
            sgxsd_aes_gcm_decrypt(
                self.key.get(),
                data.as_ptr() as *const c_void,
                data_len,
                data.as_mut_ptr() as *mut c_void,
                iv,
                aad.as_ptr() as *const c_void,
                aad_len,
                mac,
            )
        } {
            SGX_SUCCESS => Ok(()),
            error => Err(error),
        }
    }

    pub fn encrypt(&self, data: &mut [u8], aad: &[u8], iv: &AesGcmIv, mac: &mut AesGcmMac) -> Result<(), SgxStatus> {
        let data_len = data.len().to_u32().ok_or(SGX_ERROR_INVALID_PARAMETER)?;
        let aad_len = aad.len().to_u32().ok_or(SGX_ERROR_INVALID_PARAMETER)?;

        match unsafe {
            sgxsd_aes_gcm_encrypt(
                self.key.get(),
                data.as_ptr() as *const c_void,
                data_len,
                data.as_mut_ptr() as *mut c_void,
                iv,
                aad.as_ptr() as *const c_void,
                aad_len,
                mac,
            )
        } {
            SGX_SUCCESS => Ok(()),
            error => Err(error),
        }
    }

    pub const fn len() -> usize {
        let _ = sgxsd_aes_gcm_key { data: [0; 32] };
        32
    }
}

//
// SHA256Context impls
//

impl SHA256Context {
    pub const fn hash_len() -> usize {
        br_sha256_SIZE as usize
    }

    pub fn reset(&mut self) {
        unsafe { br_sha256_init(&mut self.context) };
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe { br_sha224_update(&mut self.context, data.as_ptr() as *const c_void, data.len()) };
    }

    pub fn result(&mut self, out: &mut [u8; Self::hash_len()]) {
        unsafe { br_sha256_out(&self.context, out.as_mut_ptr() as *mut c_void) }
    }

    pub fn clear(&mut self) {
        self.reset();
        clear(&mut self.context.buf);
    }
}

unsafe impl Send for br_sha256_context {}
unsafe impl Sync for br_sha256_context {}
impl Default for SHA256Context {
    fn default() -> Self {
        let mut state = Self {
            context: br_sha256_context {
                vtable: ptr::null(),
                buf:    [0; 64],
                count:  Default::default(),
                val:    Default::default(),
            },
        };
        state.reset();
        state
    }
}

pub struct SHA256HMACContext {
    key_context: br_hmac_key_context,
    context: br_hmac_context,
}

impl SHA256HMACContext {
    pub fn new(mut key: [u8; Self::hash_len()]) -> Self {
        let sha256_context: SHA256Context = Default::default();
        let mut br_key = br_hmac_key_context{
            dig_vtable: ptr::null(),
            ksi: [0; 64],
            kso: [0; 64],
        };
        unsafe {
            br_hmac_key_init(&mut br_key, sha256_context.context.vtable, key.as_mut_ptr() as *mut c_void, key.len());
        }
        let state = br_hmac_context{
            dig: Default::default(),
            kso: [0; 64],
            out_len: 0
        };
        let mut ctx = Self{
            key_context: br_key,
            context: state,
        };
        ctx.reset();
        return ctx;
    }

    pub const fn hash_len() -> usize {
        br_sha256_SIZE as usize
    }

    pub fn reset(&mut self) {
        unsafe { br_hmac_init(&mut self.context, &mut self.key_context, Self::hash_len()) };
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe { br_hmac_update(&mut self.context, data.as_ptr() as *const c_void, data.len()) };
    }

    pub fn result(&mut self, out: &mut [u8; Self::hash_len()]) {
        unsafe { br_hmac_out(&self.context, out.as_mut_ptr() as *mut c_void); }
    }

    pub fn clear(&mut self) {
        self.reset();
        clear(&mut self.context.kso);
        clear(&mut self.key_context.ksi);
        clear(&mut self.key_context.kso);
    }
}

unsafe impl Send for br_hmac_context {}
unsafe impl Sync for br_hmac_context {}

//
// Curve25519 impls
//

impl Curve25519Key {
    pub fn set_key(&mut self, privkey: &[u8; 32]) {
        *self.privkey.get_mut() = *privkey;
        curve25519_base(&mut self.pubkey, self.privkey.get());
    }

    #[allow(clippy::indexing_slicing)]
    pub fn generate(&mut self, mut rng: impl RngCore) {
        let privkey = self.privkey.get_mut();
        rng.fill_bytes(privkey);
        privkey[0] &= 248;
        privkey[31] &= 127;
        privkey[31] |= 64;
        curve25519_base(&mut self.pubkey, self.privkey.get());
    }

    pub const fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    pub fn privkey(&self) -> &[u8; 32] {
        self.privkey.get()
    }

    pub fn dh(&self, pubkey: &[u8; 32], out: &mut [u8; 32]) {
        curve25519(out, self.privkey.get(), pubkey);
    }
}

impl Default for Curve25519Key {
    fn default() -> Self {
        let mut new_self = Self {
            privkey: Default::default(),
            pubkey:  Default::default(),
        };
        new_self.generate(&mut RdRand);
        new_self
    }
}

fn curve25519_base(mypublic: &mut [u8; 32], mysecret: &[u8; 32]) {
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    curve25519(mypublic, mysecret, &basepoint)
}

fn curve25519(mypublic: &mut [u8; 32], mysecret: &[u8; 32], basepoint: &[u8; 32]) {
    unsafe { curve25519_donna(mypublic.as_mut_ptr(), mysecret.as_ptr(), basepoint.as_ptr()) };
}

#[cfg(test)]
pub mod tests {
    use super::mocks;
    use super::*;

    use crate::bindgen_wrapper::SGX_ERROR_UNEXPECTED;

    use mockers::Scenario;

    const ASSERT_RANDOM_WINDOW_SIZE: usize = 2;

    fn assert_random(src: &[u8], dst: &[u8]) {
        assert_eq!(src.len(), dst.len());
        for start in 0..=(src.len() - ASSERT_RANDOM_WINDOW_SIZE) {
            let range = start..(start + ASSERT_RANDOM_WINDOW_SIZE);
            assert_ne!(dst[range.clone()], src[range]);
        }
    }

    #[test]
    #[should_panic]
    fn test_assert_random() {
        let src = test_ffi::rand_bytes(vec![0; 100]);
        let mut data = src.clone();
        RdRand.fill_bytes(&mut data[..(src.len() - ASSERT_RANDOM_WINDOW_SIZE)]);
        assert_random(&src, &data);
    }

    #[test]
    fn fill_bytes_ok() {
        let src = test_ffi::rand_bytes(vec![0; 100]);
        let mut data = src.clone();
        RdRand.fill_bytes(&mut data[..0]);
        assert_eq!(data[..], src[..]);
        RdRand.fill_bytes(&mut data);
        assert_random(&src, &data);
    }

    #[test]
    fn try_fill_bytes_empty() {
        let scenario = Scenario::new();

        let read_rand_mock = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_READ_RAND, &scenario);
        scenario.expect(read_rand_mock.sgxsd_enclave_read_rand().never());

        let mut data = vec![0; 0];
        assert!(RdRand.try_fill_bytes(&mut data).is_ok());

        test_ffi::clear(&mocks::SGXSD_ENCLAVE_READ_RAND);
    }

    #[test]
    fn try_fill_bytes_one() {
        let scenario = Scenario::new();

        let read_rand_mock = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_READ_RAND, &scenario);
        scenario.expect(read_rand_mock.sgxsd_enclave_read_rand().and_return_clone(SGX_SUCCESS).times(1));

        let mut data = vec![0; 1];
        assert!(RdRand.try_fill_bytes(&mut data).is_ok());

        test_ffi::clear(&mocks::SGXSD_ENCLAVE_READ_RAND);
    }

    #[test]
    fn try_fill_bytes_small() {
        let scenario = Scenario::new();

        let read_rand_mock = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_READ_RAND, &scenario);
        scenario.expect(read_rand_mock.sgxsd_enclave_read_rand().and_return_clone(SGX_SUCCESS).times(1));

        let mut data = vec![0; ASSERT_RANDOM_WINDOW_SIZE];
        assert!(RdRand.try_fill_bytes(&mut data).is_ok());

        test_ffi::clear(&mocks::SGXSD_ENCLAVE_READ_RAND);
    }

    #[test]
    fn try_fill_bytes_once() {
        let scenario = Scenario::new();

        let read_rand_mock = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_READ_RAND, &scenario);
        scenario.expect(read_rand_mock.sgxsd_enclave_read_rand().and_return_clone(SGX_SUCCESS).times(1));

        let src = test_ffi::rand_bytes(vec![0; std::mem::size_of::<sgxsd_rand_buf>()]);
        let mut data = src.clone();
        assert!(RdRand.try_fill_bytes(&mut data).is_ok());
        assert_random(&src, &data);

        test_ffi::clear(&mocks::SGXSD_ENCLAVE_READ_RAND);
    }

    #[test]
    fn try_fill_bytes_multiple() {
        let scenario = Scenario::new();

        let read_rand_mock = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_READ_RAND, &scenario);
        scenario.expect(read_rand_mock.sgxsd_enclave_read_rand().and_return_clone(SGX_SUCCESS).times(4));

        let src = test_ffi::rand_bytes(vec![0; std::mem::size_of::<sgxsd_rand_buf>() * 4 - 1]);
        let mut data = src.clone();
        assert!(RdRand.try_fill_bytes(&mut data).is_ok());
        assert_random(&src, &data);

        test_ffi::clear(&mocks::SGXSD_ENCLAVE_READ_RAND);
    }

    #[test]
    fn try_fill_bytes_error() {
        let scenario = Scenario::new();

        let read_rand_mock = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_READ_RAND, &scenario);
        scenario.expect(read_rand_mock.sgxsd_enclave_read_rand().and_return(SGX_ERROR_UNEXPECTED));

        let mut data = vec![0; 1];
        assert!(RdRand.try_fill_bytes(&mut data[..0]).is_ok());
        assert!(RdRand.try_fill_bytes(&mut data).is_err());

        test_ffi::clear(&mocks::SGXSD_ENCLAVE_READ_RAND);
    }

    #[test]
    fn rand_bytes_valid() {
        let src = test_ffi::rand_bytes(vec![0; 100]);
        let data = RdRand.rand_bytes(src.clone());
        assert_eq!(data.len(), src.len());
        assert_random(&src, &data);

        let empty = RdRand.rand_bytes(vec![]);
        assert_eq!(empty.len(), 0);
    }
}
