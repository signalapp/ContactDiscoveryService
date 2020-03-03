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

#[rustfmt::skip]
#[rustfmt::skip::attributes(allow)]
#[allow(dead_code, non_camel_case_types, non_upper_case_globals, non_snake_case, improper_ctypes, clippy::all, clippy::pedantic, clippy::integer_arithmetic)]
mod bindgen_wrapper;
pub mod hash_lookup;
#[cfg(not(any(test, feature = "test")))]
mod panic;
pub mod ratelimit_set;
pub mod sgxsd;
