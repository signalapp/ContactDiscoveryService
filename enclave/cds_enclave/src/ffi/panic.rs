//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use core::panic::PanicInfo;
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { libc::abort() }
}
