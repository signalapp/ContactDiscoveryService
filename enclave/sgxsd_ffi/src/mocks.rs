//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(clippy::all, clippy::option_unwrap_used, clippy::cast_sign_loss, clippy::cast_possible_truncation)]

use std::cell::RefCell;

use mockers_derive::mocked;
use rand::distributions::*;
use rand::*;
use test_ffi::*;

pub use super::bindgen_wrapper::{sgxsd_aes_gcm_key_t, sgxsd_msg_buf_t, sgxsd_msg_from_t};

use super::bindgen_wrapper::{
    br_hash_class, br_hmac_key_context, br_hmac_context,
    br_sha1_SIZE, br_sha1_context, br_sha224_context, br_sha256_SIZE, br_sha256_context, sgx_status_t, sgxsd_aes_gcm_iv_t,
    sgxsd_aes_gcm_mac_t, sgxsd_msg_tag__bindgen_ty_1, sgxsd_msg_tag_t, sgxsd_rand_buf_t,
};
use crate::SHA256HMACContext;

//
// mock extern "C" functions
//

thread_local! {
    pub static SGXSD_ENCLAVE_SERVER_NOREPLY: RefCell<Option<SgxsdEnclaveServerNoreplyMock>> = RefCell::new(None);
    pub static SGXSD_ENCLAVE_SERVER_REPLY:   RefCell<Option<SgxsdEnclaveServerReplyMock>>   = RefCell::new(None);
    pub static SGXSD_AES_GCM_ENCRYPT:        RefCell<Option<SgxsdAesGcmEncryptMock>>        = RefCell::new(None);
    pub static SGXSD_AES_GCM_DECRYPT:        RefCell<Option<SgxsdAesGcmDecryptMock>>        = RefCell::new(None);
    pub static SGXSD_ENCLAVE_READ_RAND:      RefCell<Option<SgxsdEnclaveReadRandMock>>      = RefCell::new(None);
    pub static BEARSSL_SHA256HMAC:           RefCell<Option<BearsslSHA256HMACMock>>         = RefCell::new(None);
    pub static BEARSSL_SHA256:               RefCell<Option<BearsslSHA256Mock>>             = RefCell::new(None);
    pub static BEARSSL_SHA1:                 RefCell<Option<BearsslSHA1Mock>>               = RefCell::new(None);
}

impl std::fmt::Debug for sgxsd_msg_from_t {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

#[mocked]
pub trait SgxsdEnclaveServerNoreply {
    fn sgxsd_enclave_server_noreply(&self, from: sgxsd_msg_from_t) -> sgx_status_t;
}

#[mocked]
pub trait SgxsdEnclaveServerReply {
    fn sgxsd_enclave_server_reply(&self, reply_buf: &[u8], from: sgxsd_msg_from_t) -> sgx_status_t;
}

#[mocked]
pub trait SgxsdAesGcmEncrypt {
    fn sgxsd_aes_gcm_encrypt(&self, key: &[u8], src: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()>;
}

#[mocked]
pub trait SgxsdAesGcmDecrypt {
    fn sgxsd_aes_gcm_decrypt(&self, key: &[u8], src: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()>;
}

#[mocked]
pub trait SgxsdEnclaveReadRand {
    fn sgxsd_enclave_read_rand(&self) -> sgx_status_t;
}

#[mocked]
pub trait BearsslSHA256 {
    fn update(&self, data: &[u8]);
    fn out(&self) -> [u8; 32];
}

#[mocked]
pub trait BearsslSHA1 {
    fn update(&self, data: &[u8]);
    fn out(&self) -> [u8; 20];
}

#[mocked]
pub trait BearsslSHA256HMAC {
    fn hmac_key_init(&self, key_data: &[u8]);
    fn hmac_update(&self, data: &[u8]);
    fn hmac_out(&self) -> [u8; SHA256HMACContext::hash_len()];
}

//
// random mock values
//

impl Distribution<sgxsd_msg_tag_t> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> sgxsd_msg_tag_t {
        sgxsd_msg_tag_t {
            __bindgen_anon_1: sgxsd_msg_tag__bindgen_ty_1 { tag: rng.sample(self) },
        }
    }
}
impl Distribution<sgxsd_aes_gcm_key_t> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> sgxsd_aes_gcm_key_t {
        sgxsd_aes_gcm_key_t { data: rng.sample(self) }
    }
}
impl Distribution<sgxsd_msg_from_t> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> sgxsd_msg_from_t {
        sgxsd_msg_from_t {
            tag:        rng.sample(self),
            valid:      true,
            server_key: rng.sample(self),
        }
    }
}

//
// valid mock values
//

lazy_static::lazy_static! {
    static ref VALID_MSG_BUF: Vec<u8> = vec![0; 1];
}

pub fn valid_msg_buf() -> sgxsd_msg_buf_t {
    let msg = &VALID_MSG_BUF;
    sgxsd_msg_buf_t {
        data: msg.as_ptr() as *mut _,
        size: msg.len() as u32,
    }
}

//
// mock extern "C" function implementations
//

pub mod impls {
    use super::*;

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_noreply(from: *mut sgxsd_msg_from_t) -> sgx_status_t {
        SGXSD_ENCLAVE_SERVER_NOREPLY.with(|mock| {
            mock.borrow()
                .as_ref()
                .expect("no mock for sgxsd_enclave_server_noreply")
                .sgxsd_enclave_server_noreply(unsafe { *from })
        })
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_reply(reply_buf: sgxsd_msg_buf_t, from: *mut sgxsd_msg_from_t) -> sgx_status_t {
        assert!(!reply_buf.data.is_null());
        assert_ne!(reply_buf.size, 0);
        let reply_buf = unsafe { std::slice::from_raw_parts_mut(reply_buf.data, reply_buf.size as usize) };
        SGXSD_ENCLAVE_SERVER_REPLY.with(|mock| {
            mock.borrow()
                .as_ref()
                .expect("no mock for sgxsd_enclave_server_reply")
                .sgxsd_enclave_server_reply(reply_buf, unsafe { *from })
        })
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_aes_gcm_encrypt(
        p_key: *const sgxsd_aes_gcm_key_t,
        p_src: *const ::std::os::raw::c_void,
        src_len: u32,
        p_dst: *mut ::std::os::raw::c_void,
        p_iv: *const sgxsd_aes_gcm_iv_t,
        p_aad: *const ::std::os::raw::c_void,
        aad_len: u32,
        p_out_mac: *mut sgxsd_aes_gcm_mac_t,
    ) -> sgx_status_t
    {
        let key = unsafe { std::ptr::read_volatile(p_key) };
        assert_ne!(&key.data[..], &vec![0; key.data.len()][..]);
        assert!(!p_iv.is_null());
        let iv = unsafe { std::ptr::read_volatile(p_iv) };
        let out_mac = unsafe { p_out_mac.as_mut().expect("p_out_mac is null") };
        read_rand(&mut out_mac.data);
        if src_len != 0 {
            assert!(!p_src.is_null());
            assert!(!p_dst.is_null());
            let src = unsafe { std::slice::from_raw_parts(p_src as *const u8, src_len as usize) };
            src.iter().for_each(|p| unsafe {
                std::ptr::read_volatile(p);
            });
        }
        let aad = if aad_len != 0 {
            assert!(!p_aad.is_null());
            let aad = unsafe { std::slice::from_raw_parts(p_aad as *const u8, aad_len as usize) };
            aad.iter().for_each(|p| unsafe {
                std::ptr::read_volatile(p);
            });
            aad
        } else {
            &[]
        };
        SGXSD_AES_GCM_ENCRYPT.with(|mock| {
            if let Some(mock) = mock.borrow().as_ref() {
                let res = {
                    let src = unsafe { std::slice::from_raw_parts(p_src as *const u8, src_len as usize) };
                    mock.sgxsd_aes_gcm_encrypt(&key.data, src, &iv.data, aad)
                };
                match res {
                    Ok(data) => {
                        if src_len != 0 {
                            let dst = unsafe { std::slice::from_raw_parts_mut(p_dst as *mut u8, src_len as usize) };
                            dst.copy_from_slice(&data);
                        }
                        0
                    }
                    Err(()) => {
                        let dst = unsafe { std::slice::from_raw_parts_mut(p_dst as *mut u8, src_len as usize) };
                        dst.iter_mut().for_each(|b: &mut u8| *b = 0);
                        1
                    }
                }
            } else {
                let dst = unsafe { std::slice::from_raw_parts_mut(p_dst as *mut u8, src_len as usize) };
                read_rand(dst);
                0
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_aes_gcm_decrypt(
        p_key: *const sgxsd_aes_gcm_key_t,
        p_src: *const ::std::os::raw::c_void,
        src_len: u32,
        p_dst: *mut ::std::os::raw::c_void,
        p_iv: *const sgxsd_aes_gcm_iv_t,
        p_aad: *const ::std::os::raw::c_void,
        aad_len: u32,
        p_in_mac: *const sgxsd_aes_gcm_mac_t,
    ) -> sgx_status_t
    {
        let key = unsafe { std::ptr::read_volatile(p_key) };
        assert_ne!(&key.data[..], &vec![0; key.data.len()][..]);
        assert!(!p_iv.is_null());
        let iv = unsafe { std::ptr::read_volatile(p_iv) };
        assert!(!p_in_mac.is_null());
        unsafe { std::ptr::read_volatile(p_in_mac) };
        if src_len != 0 {
            assert!(!p_src.is_null());
            assert!(!p_dst.is_null());
            let src = unsafe { std::slice::from_raw_parts(p_src as *const u8, src_len as usize) };
            src.iter().for_each(|p| unsafe {
                std::ptr::read_volatile(p);
            });
        }
        let aad = if aad_len != 0 {
            assert!(!p_aad.is_null());
            let aad = unsafe { std::slice::from_raw_parts(p_aad as *const u8, aad_len as usize) };
            aad.iter().for_each(|p| unsafe {
                std::ptr::read_volatile(p);
            });
            aad
        } else {
            &[]
        };
        SGXSD_AES_GCM_DECRYPT.with(|mock| {
            if let Some(mock) = mock.borrow().as_ref() {
                let res = {
                    let src = unsafe { std::slice::from_raw_parts(p_src as *const u8, src_len as usize) };
                    mock.sgxsd_aes_gcm_decrypt(&key.data, src, &iv.data, aad)
                };
                match res {
                    Ok(data) => {
                        if src_len != 0 {
                            let dst = unsafe { std::slice::from_raw_parts_mut(p_dst as *mut u8, src_len as usize) };
                            dst.copy_from_slice(&data);
                        }
                        0
                    }
                    Err(()) => 1,
                }
            } else {
                let dst = unsafe { std::slice::from_raw_parts_mut(p_dst as *mut u8, src_len as usize) };
                read_rand(dst);
                0
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_read_rand(p_privkey: *mut sgxsd_rand_buf_t) -> sgx_status_t {
        assert!(!p_privkey.is_null());
        SGXSD_ENCLAVE_READ_RAND.with(|mock| {
            let res = if let Some(mock) = mock.borrow().as_ref() {
                mock.sgxsd_enclave_read_rand()
            } else {
                0
            };
            read_rand(unsafe { &mut (*p_privkey).x });
            res
        })
    }

    #[no_mangle]
    pub extern "C" fn br_sha256_init(ctx: *mut br_sha256_context) {
        unsafe { std::ptr::write_volatile(ctx, std::mem::zeroed()) };
    }

    #[no_mangle]
    pub extern "C" fn br_sha224_update(ctx: *mut br_sha224_context, data: *const ::std::os::raw::c_void, len: usize) {
        BEARSSL_SHA256.with(|mock| {
            unsafe { std::ptr::write_volatile(ctx, std::ptr::read_volatile(ctx)) };
            if len != 0 {
                assert!(!data.is_null());
                let data = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
                if let Some(mock) = mock.borrow().as_ref() {
                    mock.update(data);
                } else {
                    data.iter().for_each(|p| unsafe {
                        std::ptr::read_volatile(p);
                    });
                }
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn br_sha256_out(ctx: *const br_sha256_context, out: *mut ::std::os::raw::c_void) {
        BEARSSL_SHA256.with(|mock| {
            unsafe { std::ptr::read_volatile(ctx) };
            assert!(!out.is_null());
            let out = unsafe { std::slice::from_raw_parts_mut(out as *mut u8, br_sha256_SIZE as usize) };
            if let Some(mock) = mock.borrow().as_ref() {
                out.copy_from_slice(&mock.out());
            } else {
                read_rand(out);
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn br_sha1_init(ctx: *mut br_sha1_context) {
        unsafe { std::ptr::write_volatile(ctx, std::mem::zeroed()) };
    }

    #[no_mangle]
    pub extern "C" fn br_sha1_update(ctx: *mut br_sha1_context, data: *const ::std::os::raw::c_void, len: usize) {
        BEARSSL_SHA1.with(|mock| {
            unsafe { std::ptr::write_volatile(ctx, std::ptr::read_volatile(ctx)) };
            if len != 0 {
                assert!(!data.is_null());
                let data = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
                if let Some(mock) = mock.borrow().as_ref() {
                    mock.update(data);
                } else {
                    data.iter().for_each(|p| unsafe {
                        std::ptr::read_volatile(p);
                    });
                }
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn br_sha1_out(ctx: *const br_sha1_context, out: *mut ::std::os::raw::c_void) {
        BEARSSL_SHA1.with(|mock| {
            unsafe { std::ptr::read_volatile(ctx) };
            assert!(!out.is_null());
            let out = unsafe { std::slice::from_raw_parts_mut(out as *mut u8, br_sha1_SIZE as usize) };
            if let Some(mock) = mock.borrow().as_ref() {
                out.copy_from_slice(&mock.out());
            } else {
                read_rand(out);
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn br_hmac_key_init(kc: *mut br_hmac_key_context,
                                       digest_vtable: *const br_hash_class,
                                       key: *const ::std::os::raw::c_void,
                                       key_len: usize) {
        BEARSSL_SHA256HMAC.with(|mock| {
            unsafe { std::ptr::write_volatile(kc, std::mem::zeroed()) };
            if key_len != 0 {
                assert!(!key.is_null());
                let key_data = unsafe { std::slice::from_raw_parts(key as *const u8, key_len) };
                if let Some(mock) = mock.borrow().as_ref() {
                    mock.hmac_key_init(key_data);
                } else {
                    key_data.iter().for_each(|p| unsafe {
                        std::ptr::read_volatile(p);
                    });
                }
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn br_hmac_init(ctx: *mut br_hmac_context, kc: *const br_hmac_key_context, _out_len: usize) {
        assert!(!kc.is_null());
        unsafe { std::ptr::write_volatile(ctx, std::mem::zeroed()) };
    }

    #[no_mangle]
    pub extern "C" fn br_hmac_update(ctx: *mut br_hmac_context, data: *const libc::c_void, len: usize) {
        BEARSSL_SHA256HMAC.with(|mock| {
            unsafe { std::ptr::write_volatile(ctx, std::ptr::read_volatile(ctx)) };
            if len != 0 {
                assert!(!data.is_null());
                let data = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
                if let Some(mock) = mock.borrow().as_ref() {
                    mock.hmac_update(data);
                } else {
                    data.iter().for_each(|p| unsafe {
                        std::ptr::read_volatile(p);
                    });
                }
            }
        })
    }

    #[no_mangle]
    pub extern "C" fn br_hmac_out(ctx: *const br_hmac_context, out: *mut libc::c_void) {
        BEARSSL_SHA256HMAC.with(|mock| {
            unsafe { std::ptr::read_volatile(ctx) };
            assert!(!out.is_null());
            let out = unsafe { std::slice::from_raw_parts_mut(out as *mut u8, br_sha256_SIZE as usize) };
            if let Some(mock) = mock.borrow().as_ref() {
                out.copy_from_slice(&mock.hmac_out());
            } else {
                read_rand(out);
            }
        })

    }
}
