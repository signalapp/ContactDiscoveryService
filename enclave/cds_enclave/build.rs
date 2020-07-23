//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

fn main() -> Result<(), Box<dyn Error>> {
    if let None = env::var_os("CARGO_FEATURE_TEST") {
        println!("cargo:rustc-env=RUSTC_BOOTSTRAP=1");
    }

    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");

    run_rustc("c_src/cds-enclave-hash.rs", "c_src/cds-enclave-hash.rs.s").unwrap();
    run_rustc("c_src/cds-enclave-ratelimit-set.rs", "c_src/cds-enclave-ratelimit-set.rs.s").unwrap();

    #[cfg(feature = "cbindgen")]
    cbindgen::Builder::new()
        .with_config(cbindgen::Config {
            style: cbindgen::Style::Tag,
            ..Default::default()
        })
        .with_src("c_src/cds-enclave-hash.rs")
        .with_language(cbindgen::Language::C)
        .with_sys_include("x86intrin.h")
        .with_include_guard("_CDS_ENCLAVE_HASH_H")
        .generate()?
        .write_to_file("../include/cds-enclave-hash.h");

    #[cfg(feature = "cbindgen")]
    cbindgen::Builder::new()
        .with_src("c_src/cds-enclave-ratelimit-set.rs")
        .with_language(cbindgen::Language::C)
        .with_include_guard("_CDS_ENCLAVE_RATELIMIT_SET_H")
        .generate()?
        .write_to_file("../include/cds-enclave-ratelimit-set.h");

    cc::Build::new()
        .compiler("clang")
        .file("c_src/cds-enclave-hash.rs.s")
        .file("c_src/cds-enclave-ratelimit-set.rs.s")
        .file("c_src/cttk/int31.c")
        .include("c_src")
        .include("../include")
        .compile("cds_enclave_c");

    Ok(())
}

fn run_rustc(in_file: impl AsRef<Path>, out_file: impl AsRef<Path>) -> Result<(), ExitStatus> {
    println!("cargo:rerun-if-changed={}", in_file.as_ref().display());
    let rustc_path: PathBuf = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()).into();
    let rustflags_var = env::var("RUSTFLAGS").unwrap_or(String::new());
    let rustflags = rustflags_var.split(' ').flat_map(|flag: &str| match flag.trim() {
        flag if !flag.is_empty() => Some(flag),
        _ => None,
    });

    let mut rustc = Command::new(&rustc_path);
    #[rustfmt::skip]
    let result = rustc
        .args(&[
            "--edition=2018",
            "--crate-type", "staticlib",
            "--emit=asm",
            "-C", "opt-level=3",
            "-C", "target-cpu=skylake",
            "-C", "debuginfo=0",
            "-C", "codegen-units=1",
            "-C", "panic=abort",
            "-C", "llvm-args=-max-jump-table-size=1",
            "-C", "llvm-args=-disable-tail-duplicate",
            "-C", "no-redzone",
        ])
        .arg("-o")
        .arg(out_file.as_ref())
        .args(rustflags)
        .arg(in_file.as_ref())
        .stdin(Stdio::null())
        .status()
        .expect("error spawning rustc");
    if result.success() { Ok(()) } else { Err(result) }
}
