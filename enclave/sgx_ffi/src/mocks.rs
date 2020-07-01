//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(clippy::all, clippy::option_unwrap_used, clippy::cast_sign_loss, clippy::cast_possible_truncation)]

use std::cell::RefCell;

use mockers::matchers::*;
use mockers::*;
use mockers_derive::mocked;
use test_ffi::*;

use super::bindgen_wrapper::{
    errno_t, sgx_attributes_t, sgx_cpu_svn_t, sgx_key_id_t, sgx_measurement_t, sgx_report_body_t, sgx_report_data_t, sgx_report_t,
    sgx_status_t, sgx_target_info_t,
};

//
// mock extern "C" functions
//

thread_local! {
    pub static SGX_IS_OUTSIDE_ENCLAVE: RefCell<Option<SgxIsOutsideEnclaveMock>> = RefCell::new(None);
}

#[mocked]
pub trait SgxIsOutsideEnclave {
    fn sgx_is_outside_enclave(&self, addr: *const ::std::os::raw::c_void, size: usize) -> bool;
}

pub fn expect_sgx_is_outside_enclave(scenario: &Scenario, ptr: *const libc::c_void, size: usize, res: bool) {
    let mock = mock_for(&SGX_IS_OUTSIDE_ENCLAVE, scenario);
    scenario.expect(
        mock.sgx_is_outside_enclave(eq(ptr as *const libc::c_void), eq(size))
            .and_return(res),
    );
}

//
// mock extern "C" function implementations
//

pub mod impls {
    use super::*;

    #[no_mangle]
    pub extern "C" fn sgx_is_outside_enclave(addr: *const ::std::os::raw::c_void, size: usize) -> ::std::os::raw::c_int {
        let res = SGX_IS_OUTSIDE_ENCLAVE
            .with(|mock| (mock.borrow().as_ref().expect("no mock for sgx_is_outside_enclave")).sgx_is_outside_enclave(addr, size));
        res as i32
    }

    #[no_mangle]
    pub extern "C" fn sgx_create_report(
        target_info: *const sgx_target_info_t,
        report_data: *const sgx_report_data_t,
        report: *mut sgx_report_t,
    ) -> sgx_status_t
    {
        if !target_info.is_null() {
            unsafe { std::ptr::read_volatile(target_info) };
        }
        let mut config_id = [0; 64];
        let mut reserved4 = [0; 42];
        read_rand(&mut config_id);
        read_rand(&mut reserved4);
        unsafe {
            *report = sgx_report_t {
                body:   sgx_report_body_t {
                    cpu_svn: sgx_cpu_svn_t { svn: rand() },
                    misc_select: rand(),
                    reserved1: rand(),
                    isv_ext_prod_id: rand(),
                    attributes: sgx_attributes_t {
                        flags: rand(),
                        xfrm:  rand(),
                    },
                    mr_enclave: sgx_measurement_t { m: rand() },
                    reserved2: rand(),
                    mr_signer: sgx_measurement_t { m: rand() },
                    reserved3: rand(),
                    config_id,
                    isv_prod_id: rand(),
                    isv_svn: rand(),
                    config_svn: rand(),
                    reserved4,
                    isv_family_id: rand(),
                    report_data: *report_data,
                },
                key_id: sgx_key_id_t { id: rand() },
                mac:    rand(),
            }
        };
        0
    }

    #[no_mangle]
    pub extern "C" fn memset_s(s: *mut ::std::os::raw::c_void, smax: usize, c: ::std::os::raw::c_int, n: usize) -> errno_t {
        assert!(n <= smax);
        assert!(!s.is_null());
        unsafe {
            (s as *mut u8).write_bytes(c as u8, n);
        }
        0
    }

    #[no_mangle]
    pub extern "C" fn consttime_memequal(
        b1: *const ::std::os::raw::c_void,
        b2: *const ::std::os::raw::c_void,
        len: usize,
    ) -> ::std::os::raw::c_int
    {
        unsafe {
            let b1 = std::slice::from_raw_parts(b1 as *const u8, len);
            let b2 = std::slice::from_raw_parts(b2 as *const u8, len);
            (b1 == b2) as i32
        }
    }
}
