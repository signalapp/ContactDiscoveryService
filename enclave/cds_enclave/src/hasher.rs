//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(deprecated)]

use core::hash::{BuildHasher, SipHasher};

use rand_core::RngCore;
use sgxsd_ffi::RdRand;

#[derive(Clone)]
pub struct DefaultHasher(u64, u64);

impl Default for DefaultHasher {
    fn default() -> Self {
        Self(RdRand.next_u64(), RdRand.next_u64())
    }
}

impl BuildHasher for DefaultHasher {
    type Hasher = SipHasher;

    fn build_hasher(&self) -> Self::Hasher {
        SipHasher::new_with_keys(self.0, self.1)
    }
}
