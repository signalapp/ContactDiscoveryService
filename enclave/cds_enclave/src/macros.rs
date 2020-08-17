//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
macro_rules! static_unreachable {
    () => {{
        #[cfg(not(any(feature = "test", debug_assertions, feature = "benchmark")))]
        {
            extern "C" {
                pub fn __static_unreachable() -> !;
            }
            unsafe { __static_unreachable() };
        }
        #[cfg(any(feature = "test", debug_assertions, feature = "benchmark"))]
        unreachable!()
    }};
}
