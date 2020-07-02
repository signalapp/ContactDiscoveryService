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

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-search=native=./lib");
    println!("cargo:rustc-link-lib=static=cds_enclave_u");
    println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
    println!("cargo:rustc-link-lib=dylib=sgx_urts");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindgen::Builder::default()
        .header("src/ffi/bindgen_wrapper.h")
        .clang_arg("-I../enclave/include")
        .derive_default(true)
        .rustfmt_configuration_file(None)
        .blacklist_type("sgx_report_t")
        .blacklist_type("sgx_target_info_t")
        .blacklist_type("sgx_quote_t")
        .raw_line("use sgx_sdk_ffi::{SgxReport as sgx_report_t, SgxTargetInfo as sgx_target_info_t, SgxQuote as sgx_quote_t};")
        .prepend_enum_name(false)
        .generate()
        .expect("error generating bindings")
        .write_to_file(out_path.join("bindgen_wrapper.rs"))
        .expect("error writing bindings");

    let mut cc = cc::Build::new();
    cc.file("../enclave/include/cds_enclave_u.c")
        .include("c_src")
        .compile("cds_enclave_u");
}
