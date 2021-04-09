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

use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::mem;
use std::os::raw::*;

use sgx_sdk_ffi::*;

use super::bindgen_wrapper::{
    sgx_destroy_enclave, sgx_report_attestation_status, sgx_status_t, sgxsd_enclave_get_next_report, sgxsd_enclave_negotiate_request,
    sgxsd_enclave_node_init, sgxsd_enclave_server_call, sgxsd_enclave_server_start, sgxsd_enclave_server_stop,
    sgxsd_enclave_set_current_quote, sgxsd_msg_tag__bindgen_ty_1, sgxsd_msg_tag_t, sgxsd_node_init_args_t, CDS_ERROR_INVALID_REQUEST_SIZE,
    CDS_ERROR_QUERY_COMMITMENT_MISMATCH,
};

pub use super::bindgen_wrapper::{
    cds_encrypted_msg_t as CDSEncryptedMsg, phone_t as Phone, sgx_platform_info_t as SgxPlatformInfo,
    sgx_update_info_bit_t as SgxUpdateInfo, sgxsd_aes_gcm_iv_t as SgxsdAesGcmIv, sgxsd_aes_gcm_mac_t as SgxsdAesGcmMac,
    sgxsd_curve25519_public_key_t as SgxsdCurve25519PublicKey, sgxsd_msg_header_t as SgxsdMessageHeader,
    sgxsd_pending_request_id_t as SgxsdPendingRequestId, sgxsd_request_negotiation_request as SgxsdRequestNegotiationRequest,
    sgxsd_request_negotiation_response as SgxsdRequestNegotiationResponse, sgxsd_server_handle_call_args_t as SgxsdServerCallArgs,
    sgxsd_server_init_args_t as SgxsdServerInitArgs, sgxsd_server_state_handle_t as SgxsdServerStateHandle,
    sgxsd_server_terminate_args as ServerStopArgs, uuid_t as SgxsdUuid, SGXSD_AES_GCM_IV_SIZE, SGXSD_AES_GCM_KEY_SIZE,
    SGXSD_AES_GCM_MAC_SIZE, SGXSD_CURVE25519_KEY_SIZE, SGXSD_SHA256_HASH_SIZE,
};

pub struct MessageReply {
    pub iv: SgxsdAesGcmIv,
    pub mac: SgxsdAesGcmMac,
    pub data: Vec<u8>,
}

pub struct MessageTag {
    pub callback: Box<dyn FnOnce(SgxsdResult<MessageReply>) + Send>,
}

pub struct SgxsdQuote {
    pub gid: u32,
    pub data: Vec<u8>,
}

pub type SgxsdResult<T> = Result<T, SgxsdError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SgxsdErrorKind {
    Returned,
    Sgx,
}

#[derive(Clone, Copy)]
pub struct SgxsdError {
    pub kind: SgxsdErrorKind,
    pub status: SgxStatus,
    pub name: &'static str,
}

pub trait SgxResultExt<T> {
    fn sgxsd_context(self, name: &'static str) -> SgxsdResult<T>;
}

impl MessageTag {
    fn into_tag(self) -> sgxsd_msg_tag_t {
        sgxsd_msg_tag_t {
            __bindgen_anon_1: sgxsd_msg_tag__bindgen_ty_1 {
                p_tag: Box::into_raw(Box::new(self)) as *mut c_void,
            },
        }
    }

    pub unsafe fn from_tag(raw_tag: sgxsd_msg_tag_t) -> Option<MessageTag> {
        let p_tag = raw_tag.__bindgen_anon_1.p_tag;
        if !p_tag.is_null() {
            Some(*Box::from_raw(p_tag as *mut MessageTag))
        } else {
            None
        }
    }
}

impl SgxsdErrorKind {
    fn as_str(&self) -> &'static str {
        match self {
            SgxsdErrorKind::Returned => "returned error",
            SgxsdErrorKind::Sgx => "call failed",
        }
    }
}

impl std::error::Error for SgxsdError {}

impl fmt::Debug for SgxsdError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.status {
            SgxStatus::Success => write!(fmt, "{} {}", self.name, self.kind.as_str()),
            SgxStatus::Error(err) => write!(fmt, "{} {}: {}", self.name, self.kind.as_str(), err),
            SgxStatus::Unknown(unk) => match CdsError::try_from(unk) {
                Ok(v) => write!(fmt, "{} {}: {:?}", self.name, self.kind.as_str(), v),
                Err(_) => write!(fmt, "{} {}: unknown error code: {}", self.name, self.kind.as_str(), unk),
            },
        }
    }
}

impl fmt::Display for SgxsdError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CdsError {
    InvalidRequestSize = CDS_ERROR_INVALID_REQUEST_SIZE,
    QueryCommitmentMismatch = CDS_ERROR_QUERY_COMMITMENT_MISMATCH,
}

impl TryFrom<u32> for CdsError {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            x if x == CdsError::InvalidRequestSize as u32 => Ok(CdsError::InvalidRequestSize),
            x if x == CdsError::QueryCommitmentMismatch as u32 => Ok(CdsError::QueryCommitmentMismatch),
            _ => Err(()),
        }
    }
}

impl<T> SgxResultExt<T> for SgxResult<T> {
    fn sgxsd_context(self, name: &'static str) -> SgxsdResult<T> {
        match self {
            Ok(value) => Ok(value),
            Err(status) => Err(SgxsdError {
                kind: SgxsdErrorKind::Sgx,
                status,
                name,
            }),
        }
    }
}

impl SgxsdQuote {
    pub const SIZE: usize = mem::size_of::<SgxQuote>() - 4;
}

impl From<[u8; 16]> for SgxsdUuid {
    fn from(value: [u8; 16]) -> Self {
        Self {
            data64: [
                u64::from_ne_bytes(value[0..8].try_into().unwrap_or_else(|_| unreachable!())),
                u64::from_ne_bytes(value[8..16].try_into().unwrap_or_else(|_| unreachable!())),
            ],
        }
    }
}

impl TryFrom<&[u8]> for SgxsdUuid {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let data: [u8; 16] = value.try_into()?;
        Ok(SgxsdUuid::from(data))
    }
}

impl From<SgxsdUuid> for [u8; 16] {
    fn from(uuid: SgxsdUuid) -> Self {
        let mut bytes = [0; 16];
        &bytes[0..8].copy_from_slice(&uuid.data64[0].to_ne_bytes());
        &bytes[8..16].copy_from_slice(&uuid.data64[1].to_ne_bytes());
        bytes
    }
}

// SgxsdPendingRequestId Impls
fn pending_request_id_from_u8(value: &[u8]) -> SgxsdPendingRequestId {
    let mut pending_request_id_data = [0 as u8; std::mem::size_of::<u64>()];

    let mut start = 0;
    let mut end = start + std::mem::size_of::<u64>();
    pending_request_id_data.copy_from_slice(&value[start..end]);

    start += std::mem::size_of::<u64>();
    end += std::mem::size_of::<SgxsdAesGcmIv>();
    let mut pending_request_id_iv = [0 as u8; std::mem::size_of::<SgxsdAesGcmIv>()];
    pending_request_id_iv.copy_from_slice(&value[start..end]);

    start += std::mem::size_of::<SgxsdAesGcmIv>();
    end += std::mem::size_of::<SgxsdAesGcmMac>();
    let mut pending_request_id_mac = [0 as u8; std::mem::size_of::<SgxsdAesGcmMac>()];
    pending_request_id_mac.clone_from_slice(&value[start..end]);

    SgxsdPendingRequestId {
        data: pending_request_id_data,
        iv: SgxsdAesGcmIv {
            data: pending_request_id_iv,
        },
        mac: SgxsdAesGcmMac {
            data: pending_request_id_mac,
        },
    }
}

impl TryFrom<&[u8]> for SgxsdPendingRequestId {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < std::mem::size_of::<SgxsdPendingRequestId>() {
            return Err(());
        }
        Ok(pending_request_id_from_u8(value))
    }
}

impl TryFrom<Vec<u8>> for SgxsdPendingRequestId {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(value.as_slice().try_into()?)
    }
}

pub fn sgxsd_res<F>(ecall: F, name: &'static str) -> SgxsdResult<()>
where
    F: FnOnce(&mut sgx_status_t) -> sgx_status_t,
{
    let mut res: sgx_status_t = SgxStatus::Success.into();
    match SgxStatus::from(ecall(&mut res)) {
        SgxStatus::Success => match SgxStatus::from(res) {
            SgxStatus::Success => Ok(()),
            status => Err(SgxsdError {
                kind: SgxsdErrorKind::Returned,
                status,
                name,
            }),
        },
        status => Err(SgxsdError {
            kind: SgxsdErrorKind::Sgx,
            status,
            name,
        }),
    }
}

pub fn sgxsd_node_init(enclave_id: SgxEnclaveId, pending_requests_table_order: u8) -> SgxsdResult<()> {
    let args = sgxsd_node_init_args_t {
        pending_requests_table_order,
    };
    let () = sgxsd_res(
        |res| unsafe { sgxsd_enclave_node_init(enclave_id, res, &args) },
        "sgxsd_enclave_node_init",
    )?;
    Ok(())
}

pub fn sgxsd_negotiate_request(
    enclave_id: SgxEnclaveId,
    request: &SgxsdRequestNegotiationRequest,
) -> SgxsdResult<SgxsdRequestNegotiationResponse> {
    let mut response: SgxsdRequestNegotiationResponse = Default::default();
    let () = sgxsd_res(
        |res| unsafe { sgxsd_enclave_negotiate_request(enclave_id, res, request, &mut response) },
        "sgxsd_enclave_negotiate_request",
    )?;
    Ok(response)
}

pub fn sgxsd_get_next_quote(enclave_id: SgxEnclaveId, spid: &[u8; 16], sig_rl: &[u8]) -> SgxsdResult<SgxsdQuote> {
    let (gid, qe_target_info) = sgx_sdk_ffi::init_quote().sgxsd_context("sgx_init_quote")?;
    let mut report: SgxReport = Default::default();
    let () = sgxsd_res(
        |res| unsafe { sgxsd_enclave_get_next_report(enclave_id, res, qe_target_info, &mut report) },
        "sgxsd_enclave_get_next_quote",
    )?;
    let data = sgx_sdk_ffi::get_quote(report, spid, sig_rl).sgxsd_context("sgx_get_quote")?;
    Ok(SgxsdQuote { gid, data })
}

pub fn sgxsd_set_current_quote(enclave_id: SgxEnclaveId) -> SgxsdResult<()> {
    let () = sgxsd_res(
        |res| unsafe { sgxsd_enclave_set_current_quote(enclave_id, res) },
        "sgxsd_set_current_quote",
    )?;
    Ok(())
}

pub fn sgxsd_server_start(enclave_id: SgxEnclaveId, args: &SgxsdServerInitArgs, server_handle: SgxsdServerStateHandle) -> SgxsdResult<()> {
    let () = sgxsd_res(
        |res| unsafe { sgxsd_enclave_server_start(enclave_id, res, args, server_handle) },
        "sgxsd_enclave_server_start",
    )?;
    Ok(())
}
pub fn sgxsd_server_call(
    enclave_id: SgxEnclaveId,
    args: SgxsdServerCallArgs,
    msg_header: &SgxsdMessageHeader,
    msg_data: &[u8],
    reply_fun: impl FnOnce(SgxsdResult<MessageReply>) + Send + 'static,
    server_handle: SgxsdServerStateHandle,
) -> SgxsdResult<()> {
    let tag = MessageTag {
        callback: Box::new(reply_fun),
    }
    .into_tag();
    let () = sgxsd_res(
        |res| unsafe {
            sgxsd_enclave_server_call(
                enclave_id,
                res,
                &args,
                msg_header,
                msg_data.as_ptr() as *mut u8,
                msg_data.len().try_into().unwrap_or_else(|_| unreachable!()),
                tag,
                server_handle,
            )
        },
        "sgxsd_enclave_server_call",
    )
    .map_err(|error: SgxsdError| {
        if let Some(message_tag) = unsafe { MessageTag::from_tag(tag) } {
            (message_tag.callback)(Err(error.clone()));
        }
        error
    })?;
    Ok(())
}

pub fn sgxsd_server_stop(enclave_id: SgxEnclaveId, args: &ServerStopArgs, state_handle: SgxsdServerStateHandle) -> SgxsdResult<()> {
    let () = sgxsd_res(
        |res| unsafe { sgxsd_enclave_server_stop(enclave_id, res, args, state_handle) },
        "sgxsd_enclave_server_stop",
    )?;
    Ok(())
}

pub enum AttestationStatus {
    NoUpdateNeeded,
    UpdateNeeded(SgxUpdateInfo),
}

pub fn sgxsd_report_attestation_status(platform_info: &SgxPlatformInfo, attestation_successful: bool) -> SgxsdResult<AttestationStatus> {
    let mut update_info: SgxUpdateInfo = Default::default();
    let attest_unsuccess = (!attestation_successful) as i32;
    let status = SgxStatus::from(unsafe { sgx_report_attestation_status(platform_info, attest_unsuccess, &mut update_info) });

    let res = match status {
        SgxStatus::Success => Ok(AttestationStatus::NoUpdateNeeded),
        SgxStatus::Error(err) => {
            if err == SgxError::UpdateNeeded {
                Ok(AttestationStatus::UpdateNeeded(update_info))
            } else {
                Err(SgxStatus::Error(err))
            }
        }
        SgxStatus::Unknown(unk) => Err(SgxStatus::Unknown(unk)),
    };
    return res.map_err(|status| SgxsdError {
        kind: SgxsdErrorKind::Sgx,
        status,
        name: "sgxsd_report_attestation_status",
    });
}

pub fn sgxsd_destroy_enclave(enclave_id: SgxEnclaveId) -> SgxsdResult<()> {
    return sgxsd_res(|_res| unsafe { sgx_destroy_enclave(enclave_id) }, "sgxsd_destroy_enclave");
}

pub fn sgxsd_create_enclave(enclave_path: &str, debug: bool) -> SgxsdResult<SgxEnclaveId> {
    return sgx_sdk_ffi::create_enclave(enclave_path, debug).sgxsd_context("sgxsd_create_enclave");
}

pub fn sgxsd_init_quote() -> SgxsdResult<(u32, SgxTargetInfo)> {
    return sgx_sdk_ffi::init_quote().sgxsd_context("sgxsd_init_quote");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_u32_for_cds_error() {
        let code = CDS_ERROR_INVALID_REQUEST_SIZE;
        assert_eq!(CdsError::try_from(code), Ok(CdsError::InvalidRequestSize));

        let code = CDS_ERROR_QUERY_COMMITMENT_MISMATCH;
        assert_eq!(CdsError::try_from(code), Ok(CdsError::QueryCommitmentMismatch));

        assert_eq!(CdsError::try_from(0), Err(()));
    }

    #[test]
    fn test_try_from_u8_16_for_sgxsd_uuid() {
        let data = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

        let uuid = SgxsdUuid::from(data.clone());
        assert_eq!(uuid.data64[0], 0x0706050403020100u64);
        assert_eq!(uuid.data64[1], 0x0f0e0d0c0b0a0908u64);

        let uuid = SgxsdUuid::try_from(data.as_ref());
        assert_eq!(uuid.is_ok(), true);
        let uuid = uuid.unwrap();
        assert_eq!(uuid.data64[0], 0x0706050403020100u64);
        assert_eq!(uuid.data64[1], 0x0f0e0d0c0b0a0908u64);

        let data_short = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7];
        let bad_uuid = SgxsdUuid::try_from(data_short.as_ref());
        assert_eq!(bad_uuid.is_err(), true);

        let uuid = SgxsdUuid {
            data64: [0x0706050403020100, 0x0f0e0d0c0b0a0908],
        };
        let raw: [u8; 16] = uuid.into();
        assert_eq!(raw, data);
    }
}
