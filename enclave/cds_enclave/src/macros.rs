//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

macro_rules! static_unreachable {
    () => {{
        #[cfg(not(debug_assertions))]
        {
            extern "C" {
                pub fn __static_unreachable() -> !;
            }
            unsafe { __static_unreachable() };
        }
        #[cfg(debug_assertions)]
        unreachable!()
    }};
}
