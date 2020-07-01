//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use core::mem::MaybeUninit;

use crate::ffi::bindgen_wrapper::{cti65_t, cttk_i31_divrem, cttk_i31_init, cttk_i31_set_u64, cttk_i31_to_u64};

//
// public API
//

pub struct CtU64(CtU64Inner);

//
// private types
//

type CtU64Inner = cti65_t;

//
// CtU64 impls
//

impl CtU64 {
    const CTI_SIZE_BITS: u32 = 65;

    pub fn nan() -> Self {
        unsafe {
            let mut cti = MaybeUninit::<CtU64Inner>::uninit();
            cttk_i31_init(cti.as_mut_ptr() as *mut _, Self::CTI_SIZE_BITS);
            Self(cti.assume_init())
        }
    }

    pub fn reset(&mut self) {
        unsafe {
            cttk_i31_init(self.0.as_mut_ptr(), Self::CTI_SIZE_BITS);
        }
    }

    pub fn set(&mut self, value: u64) {
        unsafe {
            cttk_i31_set_u64(self.0.as_mut_ptr(), value);
        }
    }

    pub fn divrem(&self, rhs: &Self, quotient: &mut Self, remainder: &mut Self) {
        unsafe {
            cttk_i31_divrem(quotient.0.as_mut_ptr(), remainder.0.as_mut_ptr(), self.0.as_ptr(), rhs.0.as_ptr());
        }
    }

    pub fn divrem_assign(&mut self, rhs: &Self, remainder: &mut Self) {
        let mut quotient = Self::nan();
        self.divrem(rhs, &mut quotient, remainder);
        self.0 = quotient.0;
    }

    pub fn rem(&mut self, rhs: &Self, remainder: &mut Self) {
        let mut quotient = Self::nan();
        self.divrem(rhs, &mut quotient, remainder);
    }

    pub fn rem_assign(&mut self, rhs: &Self) {
        let mut remainder = Self::nan();
        self.rem(rhs, &mut remainder);
        self.0 = remainder.0;
    }
}

impl From<&CtU64> for u64 {
    fn from(from: &CtU64) -> Self {
        unsafe { cttk_i31_to_u64(from.0.as_ptr()) }
    }
}

impl Drop for CtU64 {
    fn drop(&mut self) {
        self.reset();
    }
}
