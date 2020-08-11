//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::env;

fn main() {
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");

    // Link to the external shared library
    println!("cargo:rustc-link-search={}/../build", project_dir);
    println!("cargo:rustc-link-lib=cds_benchmark");
}
