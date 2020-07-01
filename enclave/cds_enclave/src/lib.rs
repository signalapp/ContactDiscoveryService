//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![crate_type = "staticlib"]
#![cfg_attr(not(any(test, feature = "test")), no_std)]
#![cfg_attr(not(any(test, feature = "test")), feature(alloc_error_handler))]
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

#[cfg(not(any(test, feature = "test")))]
#[global_allocator]
static ALLOCATOR: allocator::System = allocator::System;

#[macro_use]
mod macros;

#[cfg(not(any(test, feature = "test")))]
mod allocator;
mod ffi;
mod hasher;
mod service;

pub mod external {
    use core::ptr::NonNull;

    use sgx_ffi::sgx::{SgxStatus, SGX_SUCCESS, SGX_ERROR_INVALID_PARAMETER};
    use sgxsd_ffi::ecalls::SgxsdServer;

    use super::ffi::hash_lookup::{Phone, Uuid};
    use super::service::main;

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

    #[no_mangle]
    pub extern "C" fn cds_enclave_update_ratelimit_state(
        ratelimit_state_uuid: Uuid,
        ratelimit_state_data: Option<NonNull<u8>>,
        ratelimit_state_size: usize,
        query_phones: Option<NonNull<Phone>>,
        query_phone_count: usize,
    ) -> SgxStatus
    {
        let ratelimit_state_data = match ratelimit_state_data {
            Some(ratelimit_state_data) => unsafe { core::slice::from_raw_parts_mut(ratelimit_state_data.as_ptr(), ratelimit_state_size) },
            None => return SGX_ERROR_INVALID_PARAMETER,
        };
        let query_phones = match query_phones {
            Some(query_phones) => unsafe { core::slice::from_raw_parts(query_phones.as_ptr(), query_phone_count) },
            None => return SGX_ERROR_INVALID_PARAMETER,
        };

        match main::update_ratelimit_state(ratelimit_state_uuid, ratelimit_state_data, query_phones) {
            Ok(())     => SGX_SUCCESS,
            Err(error) => error,
        }
    }

    #[no_mangle]
    pub extern "C" fn cds_enclave_delete_ratelimit_state(ratelimit_state_uuid: Uuid) -> SgxStatus {
        match main::delete_ratelimit_state(ratelimit_state_uuid) {
            Ok(())     => SGX_SUCCESS,
            Err(error) => error,
        }
    }
}

#[cfg(any(test, feature = "test"))]
pub mod test {
    pub use crate::ffi::{hash_lookup, ratelimit_set};
}
