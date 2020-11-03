//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(clippy::all, clippy::option_unwrap_used, clippy::cast_sign_loss)]

use alloc::boxed::Box;
use core::ptr;
use core::slice;

use num_traits::ToPrimitive;

use super::bindgen_wrapper::{sgxsd_enclave_server_noreply, sgxsd_enclave_server_reply};
pub use super::bindgen_wrapper::{sgxsd_msg_buf_t, sgxsd_msg_from_t};
use sgx_ffi::sgx::*;
use sgx_ffi::util::clear;

pub trait SgxsdServer: Send + Sized {
    type InitArgs;
    type HandleCallArgs;
    type TerminateArgs;

    fn init(_args: Option<&Self::InitArgs>) -> Result<Self, SgxStatus>;
    fn handle_call(
        &mut self,
        args: Option<&Self::HandleCallArgs>,
        request_data: &[u8],
        from: SgxsdMsgFrom,
    ) -> Result<(), (SgxStatus, SgxsdMsgFrom)>;
    fn terminate(self, _args: Option<&Self::TerminateArgs>) -> Result<(), SgxStatus>;
}

// wrap sgxsd_msg_from_t to make sure sgxsd_ocall_reply is called exactly once on it
unsafe impl Send for sgxsd_msg_from_t {}
pub struct SgxsdMsgFrom(Option<Box<sgxsd_msg_from_t>>);
impl SgxsdMsgFrom {
    fn new(from: &mut sgxsd_msg_from_t) -> Self {
        let mut boxed_from = Box::new(sgxsd_msg_from_t {
            valid:      from.valid,
            tag:        from.tag,
            server_key: Default::default(),
        });
        boxed_from.server_key.data.copy_from_slice(&from.server_key.data);
        let res = Self(Some(boxed_from));
        from.valid = false;
        clear(&mut from.server_key.data[..]);
        res
    }

    #[cfg(any(test, feature = "test"))]
    pub fn mock() -> Self {
        Self::new(&mut sgxsd_msg_from_t {
            tag:        Default::default(),
            valid:      true,
            server_key: Default::default(),
        })
    }

    pub fn reply(mut self, msg: &mut [u8]) -> Result<(), SgxStatus> {
        if let Some(size) = msg.len().to_u32() {
            let msg_buf = sgxsd_msg_buf_t {
                data: msg.as_mut_ptr(),
                size,
            };
            if let Some(mut msg_from) = self.0.take() {
                let msg_from_ref = &mut *msg_from;
                match unsafe { sgxsd_enclave_server_reply(msg_buf, msg_from_ref) } {
                    0 => Ok(()),
                    err => Err(err),
                }
            } else {
                Err(SGX_ERROR_INVALID_STATE)
            }
        } else {
            Err(SGX_ERROR_UNEXPECTED)
        }
    }

    fn forget(mut self) {
        if let Some(mut from) = self.0.take() {
            from.valid = false;
            clear(&mut from.server_key.data[..]);
        }
    }
}
impl Drop for SgxsdMsgFrom {
    fn drop(&mut self) {
        if let Some(mut from) = self.0.take() {
            let from_ref = &mut *from;
            unsafe { sgxsd_enclave_server_noreply(from_ref) };
        }
    }
}

pub fn sgxsd_enclave_server_init<S>(p_args: *const S::InitArgs, pp_state: *mut *mut S) -> SgxStatus
where S: SgxsdServer {
    let args = unsafe { p_args.as_ref() };
    match S::init(args) {
        Ok(new_state) => {
            unsafe { *pp_state = Box::into_raw(Box::new(new_state)) };
            0
        }
        Err(err) => err,
    }
}

pub fn sgxsd_enclave_server_handle_call<S>(
    p_args: *const S::HandleCallArgs,
    msg_buf: sgxsd_msg_buf_t,
    from: &mut sgxsd_msg_from_t,
    pp_state: *mut *mut S,
) -> SgxStatus
where
    S: SgxsdServer,
{
    let args = unsafe { p_args.as_ref() };
    let mut state = unsafe { Box::from_raw(*pp_state) };
    let msg = ECallSlice(ptr::NonNull::new(msg_buf.data as *mut _), msg_buf.size as usize);
    match state.handle_call(args, msg.as_ref(), SgxsdMsgFrom::new(from)) {
        Ok(()) => {
            unsafe { *pp_state = Box::into_raw(state) };
            0
        }
        Err((error, from)) => {
            unsafe { *pp_state = Box::into_raw(state) };
            from.forget();
            error
        }
    }
}

pub fn sgxsd_enclave_server_terminate<S>(p_args: *const S::TerminateArgs, p_state: *mut S) -> SgxStatus
where S: SgxsdServer {
    let args = unsafe { p_args.as_ref() };
    let state = unsafe { Box::from_raw(p_state) };
    match state.terminate(args) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

pub struct ECallSlice(pub Option<ptr::NonNull<u8>>, pub usize);

impl AsRef<[u8]> for ECallSlice {
    fn as_ref(&self) -> &[u8] {
        if self.1 != 0 {
            if let Some(ptr) = self.0 {
                unsafe { slice::from_raw_parts(ptr.as_ptr(), self.1) }
            } else {
                &[]
            }
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::mocks;
    use super::*;
    use mockers::{matchers::*, *};

    use super::super::bindgen_wrapper::{sgxsd_server_handle_call_args_t, sgxsd_server_init_args_t, sgxsd_server_terminate_args_t};

    fn expect_msg_from_drop(scenario: &Scenario, msg_from: &sgxsd_msg_from_t) {
        let msg_from = *msg_from;
        let mock = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_SERVER_NOREPLY, &scenario);
        scenario.expect(mock.sgxsd_enclave_server_noreply(
            check(move |check_msg_from: &sgxsd_msg_from_t|
                  unsafe { check_msg_from.tag.__bindgen_anon_1.tag == msg_from.tag.__bindgen_anon_1.tag } &&
                  check_msg_from.server_key.data == msg_from.server_key.data)
        ).and_return(0));
    }

    #[test]
    fn msg_from_drop() {
        let scenario = Scenario::new();

        let mut reply_from: sgxsd_msg_from_t = test_ffi::rand();

        expect_msg_from_drop(&scenario, &reply_from);
        drop(SgxsdMsgFrom::new(&mut reply_from));
        drop(scenario);
        test_ffi::clear(&mocks::SGXSD_ENCLAVE_SERVER_NOREPLY);
    }

    #[test]
    fn msg_from_reply() {
        let scenario = Scenario::new();

        let reply_data: Box<[u8; 32]> = Box::new(test_ffi::rand());
        let mut reply_data_2 = reply_data.clone();

        let reply_from: sgxsd_msg_from_t = test_ffi::rand();
        let mut reply_from_2 = reply_from.clone();

        let sgxsd_enclave_server_reply = test_ffi::mock_for(&mocks::SGXSD_ENCLAVE_SERVER_REPLY, &scenario);
        scenario.expect(sgxsd_enclave_server_reply
                        .sgxsd_enclave_server_reply(
                            check(move |msg_buf| *msg_buf == &reply_data[..]),
                            check(move |msg_from: &sgxsd_msg_from_t|
                                  unsafe { msg_from.tag.__bindgen_anon_1.tag == reply_from.tag.__bindgen_anon_1.tag } &&
                                  msg_from.server_key.data == reply_from.server_key.data)
                        ).and_return(0));

        SgxsdMsgFrom::new(&mut reply_from_2).reply(&mut reply_data_2[..]).unwrap();
        drop(scenario);

        test_ffi::clear(&mocks::SGXSD_ENCLAVE_SERVER_REPLY);
    }

    struct MockSgxsdServer {}
    impl SgxsdServer for MockSgxsdServer {
        type HandleCallArgs = sgxsd_server_handle_call_args_t;
        type InitArgs = sgxsd_server_init_args_t;
        type TerminateArgs = sgxsd_server_terminate_args_t;

        fn init(_args: Option<&Self::InitArgs>) -> Result<Self, SgxStatus> {
            Ok(Self {})
        }

        fn handle_call(
            &mut self,
            _args: Option<&Self::HandleCallArgs>,
            _request_data: &[u8],
            _from: SgxsdMsgFrom,
        ) -> Result<(), (SgxStatus, SgxsdMsgFrom)>
        {
            Ok(())
        }

        fn terminate(self, _args: Option<&Self::TerminateArgs>) -> Result<(), SgxStatus> {
            Ok(())
        }
    }

    fn mock_sgxsd_server() -> Box<*mut MockSgxsdServer> {
        let state = Box::new(MockSgxsdServer {});
        Box::new(Box::into_raw(state))
    }

    #[test]
    fn sgxsd_enclave_server_init_null_args() {
        let mut state: Box<*mut MockSgxsdServer> = Box::new(std::ptr::null_mut());
        sgxsd_enclave_server_init(std::ptr::null(), &mut *state);
    }

    #[test]
    fn sgxsd_enclave_server_handle_call_null_args() {
        let scenario = Scenario::new();

        let mut msg_from = test_ffi::rand();
        let mut pp_state = mock_sgxsd_server();

        expect_msg_from_drop(&scenario, &msg_from);
        sgxsd_enclave_server_handle_call(std::ptr::null(), mocks::valid_msg_buf(), &mut msg_from, &mut *pp_state);

        unsafe { Box::from_raw(*pp_state) };

        drop(scenario);
        test_ffi::clear(&mocks::SGXSD_ENCLAVE_SERVER_NOREPLY);
    }

    #[test]
    fn sgxsd_enclave_server_handle_call_empty_msg() {
        let scenario = Scenario::new();

        let mut msg_from = test_ffi::rand();
        let mut pp_state = mock_sgxsd_server();

        expect_msg_from_drop(&scenario, &msg_from);
        assert_eq!(
            sgxsd_enclave_server_handle_call(
                std::ptr::null(),
                sgxsd_msg_buf_t {
                    data: std::ptr::null_mut(),
                    size: 0,
                },
                &mut msg_from,
                &mut *pp_state
            ),
            0
        );

        unsafe { Box::from_raw(*pp_state) };

        drop(scenario);
        test_ffi::clear(&mocks::SGXSD_ENCLAVE_SERVER_NOREPLY);
    }

    #[test]
    fn sgxsd_enclave_server_handle_call_valid_msg() {
        let scenario = Scenario::new();

        let mut msg_from = test_ffi::rand();
        let mut pp_state = mock_sgxsd_server();

        expect_msg_from_drop(&scenario, &msg_from);
        assert_eq!(
            sgxsd_enclave_server_handle_call(std::ptr::null(), mocks::valid_msg_buf(), &mut msg_from, &mut *pp_state),
            0
        );

        unsafe { Box::from_raw(*pp_state) };

        drop(scenario);
        test_ffi::clear(&mocks::SGXSD_ENCLAVE_SERVER_NOREPLY);
    }

    #[test]
    fn sgxsd_enclave_server_terminate_null_args() {
        let pp_state = mock_sgxsd_server();
        sgxsd_enclave_server_terminate(std::ptr::null(), *pp_state);
    }
}
