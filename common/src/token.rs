// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Token helpers atop indirect syscalls.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

#[repr(C)]
pub struct TokenUser {
    pub sid: *mut c_void,
    pub attributes: u32,
}

/// Open the current process token. The TOKEN_QUERY mask is 0x0008.
pub unsafe fn open_current_process_token(desired_access: u32) -> Result<HANDLE, NTSTATUS> {
    use crate::syscalls::{SyscallEntry, resolve, do_syscall4};
    static ENTRY: SyscallEntry = SyscallEntry::new();
    const HASH: u32 = crate::hash::djb2(b"NtOpenProcessToken");
    let (ssn, addr) = resolve(&ENTRY, HASH).map_err(|_| -1i32)?;
    let cur_proc: HANDLE = -1_isize as HANDLE;  // (HANDLE)-1 = current process pseudo-handle
    let mut token: HANDLE = 0;
    let status = do_syscall4(
        cur_proc as usize,
        desired_access as usize,
        &mut token as *mut HANDLE as usize,
        0,
        ssn,
        addr,
    );
    if status < 0 { Err(status) } else { Ok(token) }
}

pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_USER_INFO_CLASS: u32 = 1;  // TokenUser
