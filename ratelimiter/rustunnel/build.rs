//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

fn main() {
    let mut cc = cc::Build::new();
    cc.file("c_src/malloc.c").flag("-fno-builtin").include("c_src").compile("malloc");
}
