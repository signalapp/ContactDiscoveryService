//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::ffi::c_void;
use core::iter;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::slice;

use sgx_ffi::sgx::*;
use sgx_ffi::untrusted_slice::UntrustedSlice;
use sgx_ffi::util::{memset_s, SecretValue, ToUsize};
use sgxsd_ffi::ecalls::*;
use sgxsd_ffi::{AesGcmKey, SHA256Context};

use crate::ffi::hash_lookup::*;
use crate::ffi::sgxsd::*;

//
// public API
//

pub struct SgxsdServerState {
    requests: Vec<PendingRequest>,
    query_phones: PhoneList,
}

//
// internal
//

const BYTES_PER_PHONE: usize = mem::size_of::<Phone>();
const BYTES_PER_UUID: usize = mem::size_of::<Uuid>();

const COMMITMENT_NONCE_SIZE: usize = 32;

struct PhoneList(Vec<Phone>);

struct PendingRequest {
    from: SgxsdMsgFrom,
    request_phone_count: u32,
}

pub struct Request {
    pub(crate) phones: RequestPhoneList,
}

pub struct RequestPhoneList {
    data: SecretValue<Box<[u8]>>,
}

//
// SgxsdServerState
//

impl SgxsdServerState {
    fn decode_request<'a>(&mut self, args: &'a CallArgs, request_data: &[u8]) -> Result<Request, SgxStatus> {
        if (args.query_phone_count == 0 || args.query_phone_count.to_usize() > self.query_phones.capacity() - self.query_phones.len()) {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
        return Self::decode_phone_list(args, request_data);
    }

    pub fn decode_phone_list<'a>(args: &'a CallArgs, request_data: &[u8]) -> Result<Request, SgxStatus> {
        let query_data_slice = UntrustedSlice::new(args.query.data, args.query.size.to_usize()).map_err(|_| SGX_ERROR_INVALID_PARAMETER)?;
        let mut query_phones = RequestPhoneList::new(
            query_data_slice
                .read_bytes(args.query.size.to_usize())
                .map_err(|_| SGX_ERROR_INVALID_PARAMETER)?
                .into_boxed_slice(),
        );
        let query_phones_data_len = (query_phones.data.get().len())
            .checked_sub(COMMITMENT_NONCE_SIZE)
            .ok_or(CDS_ERROR_INVALID_REQUEST_SIZE)?;

        if (request_data.len() != AesGcmKey::len()
            || query_phones_data_len % BYTES_PER_PHONE != 0
            || query_phones_data_len / BYTES_PER_PHONE != args.query_phone_count.to_usize())
        {
            return Err(CDS_ERROR_INVALID_REQUEST_SIZE);
        }

        let query_key = AesGcmKey::new(request_data)?;
        query_key.decrypt(&mut query_phones.data.get_mut()[..], &[], &args.query.iv, &args.query.mac)?;

        Self::verify_commitment(&query_phones.data.get()[..], &args.query_commitment)?;

        Ok(Request { phones: query_phones })
    }

    fn verify_commitment(data: &[u8], expected_commitment: &[u8; SHA256Context::hash_len()]) -> Result<(), SgxStatus> {
        let mut context: SHA256Context = Default::default();
        context.update(data);

        let mut commitment: [u8; SHA256Context::hash_len()] = [0; SHA256Context::hash_len()];
        context.result(&mut commitment);

        if &commitment == expected_commitment {
            Ok(())
        } else {
            Err(CDS_ERROR_QUERY_COMMITMENT_MISMATCH)
        }
    }
}

impl SgxsdServer for SgxsdServerState {
    type HandleCallArgs = CallArgs;
    type InitArgs = StartArgs;
    type TerminateArgs = StopArgs;

    fn init(args: Option<&StartArgs>) -> Result<Self, SgxStatus> {
        let args = args.ok_or(SGX_ERROR_INVALID_PARAMETER)?;

        Ok(Self {
            requests: Vec::with_capacity(args.max_query_phones.to_usize() / 4),
            query_phones: PhoneList::new(args.max_query_phones.to_usize()),
        })
    }

    fn handle_call(&mut self, args: Option<&CallArgs>, request_data: &[u8], from: SgxsdMsgFrom) -> Result<(), (SgxStatus, SgxsdMsgFrom)> {
        let args = match args {
            Some(args) => args,
            None => return Err((SGX_ERROR_INVALID_PARAMETER, from)),
        };
        let request = match self.decode_request(args, request_data) {
            Ok(request) => request,
            Err(error) => return Err((error, from)),
        };

        let request_phones_iter = request.phones.iter();
        let request_phone_count = match request_phones_iter.len().try_into() {
            Ok(request_phone_count) => request_phone_count,
            Err(_) => return Err((SGX_ERROR_INVALID_PARAMETER, from)),
        };
        self.query_phones.extend(request_phones_iter);
        self.requests.push(PendingRequest { from, request_phone_count });
        Ok(())
    }

    fn terminate(self, args: Option<&StopArgs>) -> Result<(), SgxStatus> {
        let args = args.ok_or(SGX_ERROR_INVALID_PARAMETER)?;

        let in_phones_size = (args.in_phone_count)
            .checked_mul(BYTES_PER_PHONE)
            .ok_or(SGX_ERROR_INVALID_PARAMETER)?;
        let in_uuids_size = (args.in_phone_count)
            .checked_mul(BYTES_PER_UUID)
            .ok_or(SGX_ERROR_INVALID_PARAMETER)?;

        let in_phones = UntrustedSlice::new(args.in_phones as *mut u8, in_phones_size).map_err(|_| SGX_ERROR_INVALID_PARAMETER)?;
        let in_uuids = UntrustedSlice::new(args.in_uuids as *mut u8, in_uuids_size).map_err(|_| SGX_ERROR_INVALID_PARAMETER)?;

        let query_phones_chunks = self.query_phones.chunks(MAX_HASH_TABLE_SIZE);
        let in_query_phones_result_len = (self.query_phones)
            .len()
            .checked_mul(BYTES_PER_UUID)
            .ok_or(SGX_ERROR_INVALID_PARAMETER)?;
        let mut in_query_phones_result = SecretValue::new(vec![0u8; in_query_phones_result_len]);
        let in_query_phones_result_chunks = (in_query_phones_result.get_mut()).chunks_mut(MAX_HASH_TABLE_SIZE * BYTES_PER_UUID);
        for (query_phones_chunk, in_query_phones_result_chunk) in query_phones_chunks.zip(in_query_phones_result_chunks) {
            unsafe {
                hash_lookup(
                    in_phones.as_ptr(),
                    in_uuids.as_ptr(),
                    args.in_phone_count,
                    query_phones_chunk,
                    in_query_phones_result_chunk,
                )?;
            }
        }

        let mut in_query_phones_result_remaining = &mut in_query_phones_result.get_mut()[..];
        for request in self.requests {
            let (request_in_query_phones_result, in_query_phones_result_rest) =
                in_query_phones_result_remaining.split_at_mut(request.request_phone_count.to_usize() * BYTES_PER_UUID);
            request.from.reply(request_in_query_phones_result)?;
            in_query_phones_result_remaining = in_query_phones_result_rest;
        }

        Ok(())
    }
}

//
// PhoneList
//

impl PhoneList {
    pub fn new(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }
}

impl Drop for PhoneList {
    fn drop(&mut self) {
        let byte_len = self.0.len() * mem::size_of::<Phone>();
        let clear_res = unsafe { memset_s(self.0.as_mut_ptr() as *mut c_void, byte_len, 0, byte_len) };
        assert_eq!(clear_res, 0);
    }
}

impl Deref for PhoneList {
    type Target = Vec<Phone>;

    fn deref(&self) -> &Vec<Phone> {
        &self.0
    }
}
impl DerefMut for PhoneList {
    fn deref_mut(&mut self) -> &mut Vec<Phone> {
        &mut self.0
    }
}

//
//
// RequestPhoneList
//

impl<'a> IntoIterator for &'a RequestPhoneList {
    type IntoIter = iter::Map<slice::ChunksExact<'a, u8>, fn(&[u8]) -> Phone>;
    type Item = Phone;

    fn into_iter(self) -> Self::IntoIter {
        let phones_data = self.data.get().get(COMMITMENT_NONCE_SIZE..).unwrap_or_default();
        phones_data
            .chunks_exact(mem::size_of::<Phone>())
            .map(RequestPhoneList::decode_phone)
    }
}

impl RequestPhoneList {
    fn new(data: Box<[u8]>) -> Self {
        Self {
            data: SecretValue::new(data),
        }
    }

    fn iter(&self) -> impl ExactSizeIterator<Item = Phone> + '_ {
        self.into_iter()
    }

    fn decode_phone(data: &[u8]) -> Phone {
        u64::from_ne_bytes(data.try_into().expect("chunks are of size 8"))
    }
}

//
// tests
//

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::mem;

    use mockers::matchers::*;
    use mockers::*;

    use super::*;

    lazy_static::lazy_static! {
        static ref VALID_IN_PHONES: Vec<Phone> = vec![test_ffi::rand(); 1];
        static ref VALID_IN_UUIDS:  Vec<Uuid>  = vec![Uuid { data64: test_ffi::rand() }; 1];
    }

    fn empty_init_args() -> Box<StartArgs> {
        Box::new(StartArgs {
            max_query_phones: 0,
            max_ratelimit_states: 0,
        })
    }
    fn empty_call_args() -> Box<CallArgs> {
        Box::new(Default::default())
    }
    fn empty_stop_args() -> Box<StopArgs> {
        Box::new(Default::default())
    }
    fn valid_stop_args() -> Box<StopArgs> {
        Box::new(StopArgs {
            in_phones: VALID_IN_PHONES.as_ptr() as *mut Phone,
            in_uuids: VALID_IN_UUIDS.as_ptr() as *mut Uuid,
            in_phone_count: 1,
        })
    }

    #[test]
    fn test_in_phones_outside_enclave() {
        let scenario = Scenario::new();
        let sgx_is_outside_enclave = test_ffi::mock_for(&sgx_ffi::mocks::SGX_IS_OUTSIDE_ENCLAVE, &scenario);
        scenario.expect(sgx_is_outside_enclave.sgx_is_outside_enclave(any(), any()).and_return(false));

        let server = SgxsdServerState::init(Some(&empty_init_args())).unwrap();
        server.terminate(Some(&valid_stop_args())).unwrap_err();
    }

    #[test]
    fn test_in_uuids_outside_enclave() {
        let valid_stop_args = valid_stop_args();

        let scenario = Scenario::new();
        let sgx_is_outside_enclave = test_ffi::mock_for(&sgx_ffi::mocks::SGX_IS_OUTSIDE_ENCLAVE, &scenario);
        scenario.expect(
            sgx_is_outside_enclave
                .sgx_is_outside_enclave(valid_stop_args.in_phones as *const c_void, any())
                .and_return(true),
        );
        scenario.expect(
            sgx_is_outside_enclave
                .sgx_is_outside_enclave(valid_stop_args.in_uuids as *const c_void, any())
                .and_return(false),
        );

        let server = SgxsdServerState::init(Some(&empty_init_args())).unwrap();
        server.terminate(Some(&valid_stop_args)).unwrap_err();
    }

    #[test]
    fn test_in_phones_overflow() {
        let scenario = Scenario::new();
        let sgx_is_outside_enclave = test_ffi::mock_for(&sgx_ffi::mocks::SGX_IS_OUTSIDE_ENCLAVE, &scenario);
        scenario.expect(sgx_is_outside_enclave.sgx_is_outside_enclave(any(), any()).never());

        let server = SgxsdServerState::init(Some(&empty_init_args())).unwrap();
        server
            .terminate(Some(&StopArgs {
                in_phones: VALID_IN_PHONES.as_ptr() as *mut Phone,
                in_uuids: VALID_IN_UUIDS.as_ptr() as *mut Uuid,
                in_phone_count: 1 + usize::max_value() / mem::size_of::<Phone>(),
            }))
            .unwrap_err();
    }

    #[test]
    fn test_in_uuids_overflow() {
        let scenario = Scenario::new();
        let sgx_is_outside_enclave = test_ffi::mock_for(&sgx_ffi::mocks::SGX_IS_OUTSIDE_ENCLAVE, &scenario);
        scenario.expect(sgx_is_outside_enclave.sgx_is_outside_enclave(any(), any()).never());

        let server = SgxsdServerState::init(Some(&empty_init_args())).unwrap();
        server
            .terminate(Some(&StopArgs {
                in_phones: VALID_IN_PHONES.as_ptr() as *mut Phone,
                in_uuids: VALID_IN_UUIDS.as_ptr() as *mut Uuid,
                in_phone_count: 1 + usize::max_value() / mem::size_of::<Uuid>(),
            }))
            .unwrap_err();
    }

    #[test]
    fn test_zero_max_batch() {
        let server = SgxsdServerState::init(Some(&empty_init_args())).unwrap();
        server.terminate(Some(&empty_stop_args())).unwrap();
    }

    #[test]
    fn test_empty_batch() {
        let valid_stop_args = valid_stop_args();

        let scenario = Scenario::new();
        let sgx_is_outside_enclave = test_ffi::mock_for(&sgx_ffi::mocks::SGX_IS_OUTSIDE_ENCLAVE, &scenario);
        scenario.expect(
            sgx_is_outside_enclave
                .sgx_is_outside_enclave(valid_stop_args.in_phones as *const c_void, any())
                .and_return(true),
        );
        scenario.expect(
            sgx_is_outside_enclave
                .sgx_is_outside_enclave(valid_stop_args.in_uuids as *const c_void, any())
                .and_return(true),
        );

        let server = SgxsdServerState::init(Some(&StartArgs {
            max_query_phones: 1,
            max_ratelimit_states: 0,
        }))
        .unwrap();
        server.terminate(Some(&valid_stop_args)).unwrap();
    }

    #[test]
    fn test_empty_msg() {
        let scenario = Scenario::new();
        scenario.expect(
            test_ffi::mock_for(&sgxsd_ffi::mocks::SGXSD_ENCLAVE_SERVER_NOREPLY, &scenario)
                .sgxsd_enclave_server_noreply(any())
                .and_return(SGX_SUCCESS),
        );

        let mut server = SgxsdServerState::init(Some(&StartArgs {
            max_query_phones: 1,
            max_ratelimit_states: 0,
        }))
        .unwrap();
        assert_eq!(
            server
                .handle_call(Some(&empty_call_args()), &[], SgxsdMsgFrom::mock())
                .unwrap_err()
                .0,
            SGX_ERROR_INVALID_PARAMETER
        );
        server.terminate(Some(&empty_stop_args())).unwrap();
    }
}
