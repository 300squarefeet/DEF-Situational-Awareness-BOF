#![cfg(target_arch = "x86")]
use core::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_USER_INFO_CLASS: u32 = 1;
pub struct TokenUser { pub sid: *mut c_void, pub attributes: u32 }

pub unsafe fn open_current_process_token(desired_access: u32) -> Result<HANDLE, NTSTATUS> {
    #[link(name = "advapi32")]
    unsafe extern "system" { fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32; }
    let mut token: HANDLE = 0;
    if OpenProcessToken(-1isize as HANDLE, desired_access, &mut token) != 0 { Ok(token) } else { Err(-1) }
}
