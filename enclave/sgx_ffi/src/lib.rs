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
pub mod sgx;
pub mod untrusted_slice;
pub mod util;

#[cfg(any(test, feature = "test"))]
pub mod mocks;
