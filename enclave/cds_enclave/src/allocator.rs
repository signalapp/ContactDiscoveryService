//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use alloc::alloc::*;
use core::cmp;
use core::ptr;

#[cfg(target_arch = "x86_64")]
const MIN_ALIGN: usize = 8;

pub struct System;
unsafe impl GlobalAlloc for System {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() {
            libc::malloc(layout.size()) as *mut u8
        } else {
            libc::memalign(layout.align(), layout.size()) as *mut u8
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() {
            libc::calloc(layout.size(), 1) as *mut u8
        } else {
            let ptr = self.alloc(layout.clone());
            if !ptr.is_null() {
                ptr::write_bytes(ptr, 0, layout.size());
            }
            ptr
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        libc::free(ptr as *mut libc::c_void)
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= MIN_ALIGN && layout.align() <= new_size {
            libc::realloc(ptr as *mut libc::c_void, new_size) as *mut u8
        } else {
            realloc_fallback(self, ptr, layout, new_size)
        }
    }
}

unsafe fn realloc_fallback(alloc: &System, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
    let new_layout = Layout::from_size_align_unchecked(new_size, old_layout.align());

    let new_ptr = GlobalAlloc::alloc(alloc, new_layout);
    if !new_ptr.is_null() {
        let size = cmp::min(old_layout.size(), new_size);
        ptr::copy_nonoverlapping(ptr, new_ptr, size);
        GlobalAlloc::dealloc(alloc, ptr, old_layout);
    }
    new_ptr
}

#[alloc_error_handler]
pub fn handle_alloc_error(layout: Layout) -> ! {
    let status = sgx_ffi::util::MemoryStatus::collect();
    panic!(
        "out of memory allocating {} bytes with {} used of {} bytes in {} chunks",
        layout.size(),
        status.used_bytes,
        status.footprint_bytes,
        status.free_chunks
    );
}
