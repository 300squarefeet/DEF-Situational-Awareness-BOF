// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Dynamic Function Resolution by PEB walk + djb2 hash.
//! Cached per-call-site via `AtomicPtr`. Public macro: `dfr_fn!`.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Resolve `<module>!<api>` by hash. Implementation reuses the helpers in
/// `crate::syscalls` (`find_module`, `find_export`) — kept in syscalls.rs
/// because they're shared between syscall and DFR paths.
pub unsafe fn resolve_api(module_hash: u32, api_hash: u32) -> Option<*mut c_void> {
    #[cfg(target_arch = "x86_64")]
    {
    let m = crate::syscalls::find_module_pub(module_hash)?;
    crate::syscalls::find_export_pub(m, api_hash)
    }
    #[cfg(target_arch = "x86")]
    {
        let _ = (module_hash, api_hash);
        None
    }
}

#[cfg(target_arch = "x86")]
pub unsafe fn resolve_api_name(module: &[u8], api: &[u8]) -> Option<*mut c_void> {
    // x86 currently has no 64-bit PEB/export walker. Keep the same DFR call
    // surface and resolve through kernel32 only for the legacy target.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleA(name: *const u8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }
    let mut m = [0u8; 96];
    let mut a = [0u8; 96];
    let ml = module.len().min(m.len() - 1);
    let al = api.len().min(a.len() - 1);
    m[..ml].copy_from_slice(&module[..ml]);
    a[..al].copy_from_slice(&api[..al]);
    let h = GetModuleHandleA(m.as_ptr());
    if h.is_null() { return None; }
    let p = GetProcAddress(h, a.as_ptr());
    if p.is_null() { None } else { Some(p) }
}

/// Cached single-pointer slot. Use through `dfr_fn!`.
pub struct DfrCache(pub AtomicPtr<c_void>);
impl DfrCache {
    pub const fn new() -> Self { Self(AtomicPtr::new(core::ptr::null_mut())) }
}

#[macro_export]
macro_rules! dfr_fn {
    (
        $fn_name:ident( $($arg:ident : $argty:ty),* $(,)? ) -> $ret:ty,
        module = $module:literal,
        api    = $api:literal $(,)?
    ) => {
        pub unsafe fn $fn_name($($arg : $argty),*) -> ::core::result::Result<$ret, &'static str> {
            static CACHE: $crate::dfr::DfrCache = $crate::dfr::DfrCache::new();
            const M: u32 = $crate::hash::djb2_case_insensitive($module.as_bytes());
            const A: u32 = $crate::hash::djb2($api.as_bytes());
            let cached = CACHE.0.load(::core::sync::atomic::Ordering::Acquire);
            let ptr = if cached.is_null() {
                let p = {
                    #[cfg(target_arch = "x86_64")]
                    { $crate::dfr::resolve_api(M, A) }
                    #[cfg(target_arch = "x86")]
                    { $crate::dfr::resolve_api_name($module.as_bytes(), $api.as_bytes()) }
                }.ok_or("dfr: api not found")?;
                CACHE.0.store(p, ::core::sync::atomic::Ordering::Release);
                p
            } else { cached };
            type FnT = unsafe extern "system" fn($($argty),*) -> $ret;
            let f: FnT = ::core::mem::transmute(ptr);
            Ok(f($($arg),*))
        }
    };
}
