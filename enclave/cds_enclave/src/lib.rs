/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

#[cfg(not(any(test, feature = "test")))]
mod allocator;
mod ffi;
mod hasher;
mod service;

pub mod external {
    use sgx_ffi::sgx::SgxStatus;
    use sgxsd_ffi::ecalls::SgxsdServer;

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
}

#[cfg(any(test, feature = "test"))]
pub mod test {
    pub use crate::ffi::{hash_lookup, ratelimit_set};
}
