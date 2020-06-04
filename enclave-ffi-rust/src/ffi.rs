/*
 * Copyright (C) 2020 Signal Messenger, LLC.
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

#[allow(
    dead_code,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    improper_ctypes
)]
mod bindgen_wrapper {
    include!(concat!(env!("OUT_DIR"), "/bindgen_wrapper.rs"));
}

pub mod ocalls;
pub mod sgxsd;
