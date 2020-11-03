//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![crate_type = "staticlib"]
#![cfg_attr(not(any(test, feature = "test", feature = "benchmark")), no_std)]
#![cfg_attr(not(any(test, feature = "test", feature = "benchmark")), feature(alloc_error_handler))]
#![allow(unused_parens, clippy::style, clippy::large_enum_variant)]
#![warn(
    bare_trait_objects,
    elided_lifetimes_in_paths,
    trivial_numeric_casts,
    variant_size_differences,
    clippy::integer_arithmetic,
    clippy::wildcard_enum_match_arm
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
    clippy::use_underscore_binding
)]

extern crate alloc;

#[cfg(not(any(test, feature = "test", feature = "benchmark")))]
#[global_allocator]
static ALLOCATOR: allocator::System = allocator::System;

#[macro_use]
mod macros;

#[cfg(not(any(test, feature = "test", feature = "benchmark")))]
mod allocator;
pub mod ffi;
mod hasher;
mod service;

pub mod external {
    use sgx_ffi::sgx::{SgxStatus, SGX_SUCCESS, SGX_ERROR_INVALID_PARAMETER};
    use sgxsd_ffi::ecalls::{SgxsdServer, ECallSlice};

    use super::service::main;
    use sgxsd_ffi::SHA256HMACContext;
    use crate::ffi::sgxsd::CallArgs;
    use crate::service::main::SgxsdServerState;
    use core::{slice, ptr};

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_init(
        p_args: *const <main::SgxsdServerState as SgxsdServer>::InitArgs,
        pp_state: *mut *mut main::SgxsdServerState,
    ) -> SgxStatus
    {
        sgxsd_ffi::ecalls::sgxsd_enclave_server_init(p_args, pp_state)
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_handle_call(
        p_args: *const <main::SgxsdServerState as SgxsdServer>::HandleCallArgs,
        msg_buf: sgxsd_ffi::ecalls::sgxsd_msg_buf_t,
        mut from: sgxsd_ffi::ecalls::sgxsd_msg_from_t,
        pp_state: *mut *mut main::SgxsdServerState,
    ) -> SgxStatus
    {
        sgxsd_ffi::ecalls::sgxsd_enclave_server_handle_call(p_args, msg_buf, &mut from, pp_state)
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_terminate(
        p_args: *const <main::SgxsdServerState as SgxsdServer>::TerminateArgs,
        p_state: *mut main::SgxsdServerState,
    ) -> SgxStatus
    {
        sgxsd_ffi::ecalls::sgxsd_enclave_server_terminate(p_args, p_state)
    }

    // fingerprint must be allocated by the caller, and should be the same size as call_args.query_phone_count.
    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_create_ratelimit_fingerprint<'a>(
        fingerprint_key: [u8; 32],
        call_args: &'a CallArgs,
        msg_buf: sgxsd_ffi::ecalls::sgxsd_msg_buf_t,
        _from: &mut sgxsd_ffi::ecalls::sgxsd_msg_from_t,
        fingerprint_raw: *mut u8,
        fingerprint_size: usize,
    ) -> SgxStatus
    {
        let request_data = ECallSlice(ptr::NonNull::new(msg_buf.data as *mut _), msg_buf.size as usize);
        let request = match SgxsdServerState::decode_phone_list(call_args, request_data.as_ref()) {
            Ok(request) => request,
            Err(error) => {
                return error
            },
        };

        let fingerprint = unsafe {slice::from_raw_parts_mut(fingerprint_raw, fingerprint_size)};
        let mut ctx = SHA256HMACContext::new(fingerprint_key);
        for (i, phone) in request.phones.into_iter().enumerate() {
            if (i >= fingerprint_size) {
                return SGX_ERROR_INVALID_PARAMETER;
            }
            ctx.update(&phone.to_le_bytes());
            let phone_out = &mut [0; SHA256HMACContext::hash_len()];
            ctx.result(phone_out);
            fingerprint[i] = phone_out[0];
            ctx.reset();
        }
        return SGX_SUCCESS;
    }
}

#[cfg(any(test, feature = "test"))]
pub mod test {
    pub use crate::ffi::hash_lookup;
    use mockers::{Scenario, Sequence};
    use crate::external::sgxsd_enclave_create_ratelimit_fingerprint;
    use crate::ffi::sgxsd::{CallArgs, EncryptedMessage};
    use core::ptr;
    use sgxsd_ffi::{mocks, SHA256Context, SHA256HMACContext};
    use mockers::matchers::{check, any};

    #[test]
    fn sgxsd_enclave_create_ratelimit_fingerprint_valid() {
        let scenario = Scenario::new();
        let mut fingerprint_key: [u8; 32] = test_ffi::rand();
        let mut msg_from = test_ffi::rand();
        let mut data_arr= [2; 32+8+8]; // 32 byte nonce plus 8 bytes for each phone number
        test_ffi::read_rand(&mut data_arr[..]);
        let query = EncryptedMessage{
            iv: Default::default(),
            mac: Default::default(),
            size: data_arr.len() as u32,
            data: data_arr.as_mut_ptr(),
        };


        let mut phone_list: Vec<u8> = vec![3; 32]; // These first 32-bytes are the nonce for the commitment
        let raw_phones: Vec<u64> = vec![15558275309, 18002738255];
        let actual_phone_bytes: Vec<[u8; 8]> = raw_phones.into_iter().map(|x| x.to_le_bytes()).collect();
        let fake_phone_bytes: Vec<u8> = actual_phone_bytes.clone().into_iter().map(|v| v.to_vec()).flatten().collect();

        phone_list.append(&mut fake_phone_bytes.clone());
        let mut context: SHA256Context = Default::default();
        context.update(&phone_list[..]);
        let mut commitment = [0; SHA256Context::hash_len()];
        context.result(&mut commitment);

        let call_args = CallArgs {
            query_phone_count: 2,
            ratelimit_state_size: 0,
            ratelimit_state_uuid: Default::default(),
            ratelimit_state_data: ptr::null_mut(),
            query: query,
            query_commitment: commitment,
        };

        let mut fake_request_data = [1; 32];
        let msg = sgxsd_ffi::ecalls::sgxsd_msg_buf_t{
            data: fake_request_data.as_mut_ptr(),
            size: fake_request_data.len() as u32,
        };
        let sgx_is_outside_enclave_mock = test_ffi::mock_for(&sgx_ffi::mocks::SGX_IS_OUTSIDE_ENCLAVE, &scenario);
        scenario.expect(sgx_is_outside_enclave_mock.sgx_is_outside_enclave(data_arr.as_mut_ptr() as *const core::ffi::c_void, data_arr.len()).and_return(true));
        let decrypt_mock = test_ffi::mock_for(&mocks::SGXSD_AES_GCM_DECRYPT, &scenario);
        scenario.expect(decrypt_mock.sgxsd_aes_gcm_decrypt(
            check(move |key| *key == &fake_request_data),
            check(move |src| *src == &data_arr[..]),
            any(), any()).and_return(Ok(phone_list.to_vec())));

        let hash_mock = test_ffi::mock_for(&mocks::BEARSSL_SHA256, &scenario);
        let phone_list_slice = phone_list.to_vec();
        scenario.expect(hash_mock.update(
            check(move |data| *data == &phone_list_slice[..])).and_return(()));
        scenario.expect(hash_mock.out().and_return(commitment));

        // If you start getting mock failures around `BearSSLSHA256Mock.out`from these lines, it's
        // because they got turned into i32s instead of the u8s they're coerced to in this version
        // of the code. You could fix that with `as u8` on their contents and eat the
        // trivial_numeric_cast warnings, or put back the assertion the makes the coercions happen.
        let fake_hmac1 = [4; SHA256HMACContext::hash_len()];
        let fake_hmac2 = [5; SHA256HMACContext::hash_len()];
        let hmac_mock = test_ffi::mock_for(&mocks::BEARSSL_SHA256HMAC, &scenario);

        let mut hmac_out_seq = Sequence::new();
        hmac_out_seq.expect(hmac_mock.hmac_key_init(
            check(move |key_data| *key_data == &fingerprint_key[..])).and_return(()));

        let first_phone = actual_phone_bytes[0];
        hmac_out_seq.expect(hmac_mock.hmac_update(
            check(move |phone_bytes| *phone_bytes == first_phone)).and_return(()));
        hmac_out_seq.expect(hmac_mock.hmac_out().and_return(fake_hmac1));
        hmac_out_seq.expect(hmac_mock.hmac_update(
            check(move |phone_bytes| *phone_bytes == actual_phone_bytes[1])).and_return(()));
        hmac_out_seq.expect(hmac_mock.hmac_out().and_return(fake_hmac2));
        scenario.expect(hmac_out_seq);
        let mut fingerprint_out = vec![0; call_args.query_phone_count as usize];
        assert_eq!(
            sgxsd_enclave_create_ratelimit_fingerprint(fingerprint_key, &call_args, msg, &mut msg_from, fingerprint_out.as_mut_ptr(), call_args.query_phone_count as usize),
            0
        );

        assert_eq!(fingerprint_out, vec![fake_hmac1[0], fake_hmac2[0]]);
        drop(scenario);
        test_ffi::clear(&mocks::BEARSSL_SHA256HMAC);
    }

}
