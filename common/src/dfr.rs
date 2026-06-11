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
    let m = crate::syscalls::find_module_pub(module_hash)?;
    crate::syscalls::find_export_pub(m, api_hash)
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
                let p = $crate::dfr::resolve_api(M, A).ok_or("dfr: api not found")?;
                CACHE.0.store(p, ::core::sync::atomic::Ordering::Release);
                p
            } else { cached };
            type FnT = unsafe extern "system" fn($($argty),*) -> $ret;
            let f: FnT = ::core::mem::transmute(ptr);
            Ok(f($($arg),*))
        }
    };
}
