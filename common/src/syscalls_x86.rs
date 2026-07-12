#![cfg(target_arch = "x86")]
use core::ffi::c_void;
use windows_sys::Win32::Foundation::NTSTATUS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError { Unsupported }

pub struct SyscallEntry;
impl SyscallEntry { pub const fn new() -> Self { Self } }

pub unsafe fn resolve(_: &SyscallEntry, _: u32) -> Result<(u16, usize), SyscallError> { Err(SyscallError::Unsupported) }
pub unsafe fn resolve_ssn(_: u32) -> Result<(u16, usize), SyscallError> { Err(SyscallError::Unsupported) }
pub unsafe fn find_module_pub(_: u32) -> Option<*mut c_void> { None }
pub unsafe fn find_export_pub(_: *mut c_void, _: u32) -> Option<*mut c_void> { None }

pub unsafe extern "system" fn do_syscall4(_: usize, _: usize, _: usize, _: usize, _: u16, _: usize) -> NTSTATUS { -1 }
pub unsafe extern "system" fn do_syscall5(_: usize, _: usize, _: usize, _: usize, _: usize, _: u16, _: usize) -> NTSTATUS { -1 }
pub unsafe extern "system" fn do_syscall6(_: usize, _: usize, _: usize, _: usize, _: usize, _: usize, _: u16, _: usize) -> NTSTATUS { -1 }
pub unsafe extern "system" fn do_syscall10(_: usize, _: usize, _: usize, _: usize, _: usize, _: usize, _: usize, _: usize, _: usize, _: usize, _: u16, _: usize) -> NTSTATUS { -1 }
