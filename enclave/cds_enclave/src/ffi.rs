//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#[rustfmt::skip]
#[rustfmt::skip::attributes(allow)]
#[allow(dead_code, non_camel_case_types, non_upper_case_globals, non_snake_case, improper_ctypes, clippy::all, clippy::pedantic, clippy::integer_arithmetic)]
mod bindgen_wrapper;
pub mod hash_lookup;
#[cfg(not(any(test, feature = "test", feature = "benchmark")))]
mod panic;
pub mod sgxsd;
