//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use alloc::vec::Vec;
use core::mem;
use core::ptr;
use core::slice;

use super::bindgen_wrapper::{sgx_attributes_t, sgx_create_report, sgx_measurement_t, sgx_report_data_t, sgx_target_info_t};
pub use super::bindgen_wrapper::{
    sgx_report_t as SgxReport, sgx_status_t as SgxStatus, SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_INVALID_STATE, SGX_ERROR_UNEXPECTED,
    SGX_SUCCESS,
};

pub struct SgxTargetInfo<'a> {
    pub mrenclave:   &'a [u8],
    pub flags:       u64,
    pub xfrm:        u64,
    pub misc_select: u32,
    pub config_svn:  u16,
    pub config_id:   &'a [u8],
}

pub fn create_report(qe_target_info: &SgxTargetInfo<'_>, report_data_in: &[u8]) -> Result<Vec<u8>, SgxStatus> {
    let mut sgx_qe_target_info = sgx_target_info_t {
        mr_enclave:  sgx_measurement_t { m: [0; 32] },
        attributes:  sgx_attributes_t {
            flags: qe_target_info.flags,
            xfrm:  qe_target_info.xfrm,
        },
        reserved1:   [0; 2],
        config_svn:  qe_target_info.config_svn,
        misc_select: qe_target_info.misc_select,
        reserved2:   [0; 8],
        config_id:   [0; 64],
        reserved3:   [0; 384],
    };
    if qe_target_info.mrenclave.len() != sgx_qe_target_info.mr_enclave.m.len() {
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }
    if qe_target_info.config_id.len() != sgx_qe_target_info.config_id.len() {
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }
    sgx_qe_target_info.mr_enclave.m.copy_from_slice(qe_target_info.mrenclave);
    sgx_qe_target_info.config_id.copy_from_slice(qe_target_info.config_id);
    let report = create_report_raw(Some(&sgx_qe_target_info), report_data_in)?;
    let report_ref = &report;
    unsafe {
        let report_slice = slice::from_raw_parts(report_ref as *const SgxReport as *const u8, mem::size_of::<SgxReport>());
        Ok(report_slice.to_vec())
    }
}

pub fn create_report_raw(qe_target_info: Option<&sgx_target_info_t>, report_data_in: &[u8]) -> Result<SgxReport, SgxStatus> {
    let mut report_data = sgx_report_data_t { d: [0; 64] };
    if let Some(()) = report_data.d.get_mut(..report_data_in.len()).map(|report_data_part| {
        report_data_part.copy_from_slice(report_data_in);
    }) {
        let mut report: SgxReport = unsafe { mem::zeroed() };
        let res = unsafe {
            if let Some(qe_target_info) = qe_target_info {
                sgx_create_report(qe_target_info, &report_data, &mut report)
            } else {
                sgx_create_report(ptr::null(), &report_data, &mut report)
            }
        };
        if res == SGX_SUCCESS { return Ok(report) } else { return Err(res) }
    } else {
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }
}

#[cfg(test)]
pub mod tests {
    use test_ffi::rand_bytes;

    use super::*;

    fn target_info<'a>(mrenclave: &'a [u8], config_id: &'a [u8]) -> SgxTargetInfo<'a> {
        SgxTargetInfo {
            mrenclave,
            flags: Default::default(),
            xfrm: Default::default(),
            misc_select: Default::default(),
            config_svn: Default::default(),
            config_id,
        }
    }

    #[test]
    fn create_report_bad_args() {
        let dummy_target_info = sgx_target_info_t::default();

        let qe_mrenclave = rand_bytes(vec![0; std::mem::size_of_val(&dummy_target_info.mr_enclave)]);
        let qe_config_id = rand_bytes(vec![0; std::mem::size_of_val(&dummy_target_info.config_id)]);
        let qe_target_info = target_info(&qe_mrenclave, &qe_config_id);
        let bad_report_data = rand_bytes(vec![0; std::mem::size_of::<sgx_report_data_t>() + 1]);

        assert_eq!(
            Err(SGX_ERROR_INVALID_PARAMETER),
            create_report(&target_info(&[], &qe_config_id), &[])
        );
        assert_eq!(
            Err(SGX_ERROR_INVALID_PARAMETER),
            create_report(&target_info(&[0], &qe_config_id), &[])
        );
        assert_eq!(
            Err(SGX_ERROR_INVALID_PARAMETER),
            create_report(&target_info(&qe_mrenclave, &[]), &[])
        );
        assert_eq!(
            Err(SGX_ERROR_INVALID_PARAMETER),
            create_report(&target_info(&qe_mrenclave, &[0]), &[])
        );
        assert_eq!(Err(SGX_ERROR_INVALID_PARAMETER), create_report(&qe_target_info, &bad_report_data));
        assert!(create_report(&qe_target_info, &[]).is_ok());
    }

    #[test]
    fn create_report_valid() {
        let dummy_target_info = sgx_target_info_t::default();

        let qe_mrenclave = rand_bytes(vec![0; std::mem::size_of_val(&dummy_target_info.mr_enclave)]);
        let qe_config_id = rand_bytes(vec![0; std::mem::size_of_val(&dummy_target_info.config_id)]);
        let qe_target_info = target_info(&qe_mrenclave, &qe_config_id);
        let report_data = rand_bytes(vec![0; std::mem::size_of::<sgx_report_data_t>()]);

        for report_data_len in 0..=report_data.len() {
            let res = create_report(&qe_target_info, &report_data[..report_data_len]);
            assert!(res.is_ok());
            if let Ok(report_bytes) = res {
                let report: SgxReport = unsafe { std::ptr::read_unaligned(report_bytes.as_ptr() as *const SgxReport) };
                assert_eq!(&report_data[..report_data_len], &report.body.report_data.d[..report_data_len]);
                assert_eq!(
                    &report.body.report_data.d[report_data_len..],
                    &vec![0; report.body.report_data.d.len() - report_data_len][..]
                );
            }
        }
    }
}
