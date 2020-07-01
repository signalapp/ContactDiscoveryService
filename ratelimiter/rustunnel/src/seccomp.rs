//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::*;
use std::ffi::CStr;
use std::fs;
use std::os::unix::prelude::*;
use std::panic;
use std::path::Path;
use std::ptr::NonNull;

use failure::{format_err, ResultExt};
use nix::errno::Errno;
use nix::unistd;
use seccomp_sys::*;

use crate::util;

pub struct SeccompContext {
    context: NonNull<scmp_filter_ctx>,
}

pub fn configure_malloc() -> Result<(), failure::Error> {
    // mainly to ensure dlmalloc is initialized
    if unsafe { libc::mallopt(libc::M_MMAP_THRESHOLD, 0) } != 1 {
        return Err(failure::format_err!("error setting mallopt M_MMAP_THRESHOLD to 0"));
    }

    Ok(())
}

pub fn close_all_fds(keep_fds: &BTreeSet<RawFd>) -> Result<(), failure::Error> {
    let fd_dir = fs::read_dir(Path::new(r"/proc/self/fd/")).context("error reading /proc/self/fd/")?;
    let mut fds = BTreeSet::new();
    for dir_entry_result in fd_dir {
        let fd_name = dir_entry_result.context("error reading /proc/self/fd/")?.file_name();
        let fd = fd_name
            .to_string_lossy()
            .parse::<RawFd>()
            .with_context(|_| format_err!("invalid fd number in /proc/self/fd/: {:?}", fd_name))?;
        fds.insert(fd);
    }
    for fd in fds.difference(&keep_fds) {
        match unistd::close(*fd) {
            Ok(()) => (),
            Err(nix::Error::Sys(Errno::EBADF)) => (),
            Err(error) => util::convert_nix(Err(error))?,
        }
    }
    Ok(())
}

pub fn configure_panic_hook() {
    let default_panic_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info: &panic::PanicInfo<'_>| {
        default_panic_hook(panic_info);
        // trigger abort via double panic
        panic!("aborting")
    }));
}

//
// SeccompContext impls
//

impl SeccompContext {
    pub fn new() -> Result<Self, ()> {
        let context = NonNull::new(unsafe { seccomp_init(SCMP_ACT_KILL_PROCESS) }).ok_or(())?;
        Ok(Self { context })
    }

    pub fn allow(&mut self, syscall_name: &CStr) -> Result<(), Errno> {
        let syscall_nr = unsafe { seccomp_syscall_resolve_name(syscall_name.as_ptr()) };
        assert_eq!(
            0,
            errno_result(unsafe { seccomp_rule_add(self.context.as_ptr(), SCMP_ACT_ALLOW, syscall_nr, 0) })?
        );
        Ok(())
    }

    pub fn deny_errno(&mut self, syscall_name: &CStr, errno: Errno) -> Result<(), Errno> {
        let syscall_nr = unsafe { seccomp_syscall_resolve_name(syscall_name.as_ptr()) };
        assert_eq!(
            0,
            errno_result(unsafe { seccomp_rule_add(self.context.as_ptr(), SCMP_ACT_ERRNO(errno as u32), syscall_nr, 0) })?
        );
        Ok(())
    }

    pub fn load(&mut self) -> Result<(), Errno> {
        assert_eq!(0, errno_result(unsafe { seccomp_load(self.context.as_ptr()) })?);
        Ok(())
    }
}

impl Drop for SeccompContext {
    fn drop(&mut self) {
        unsafe { seccomp_release(self.context.as_ptr()) };
    }
}

//
// internal
//

fn errno_result(result: i32) -> Result<i32, Errno> {
    if result >= 0 { Ok(result) } else { Err(Errno::from_i32(-result)) }
}
