// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! RAII wrappers for COM lifetime management. Every COM pointer goes through
//! `ComRef<T>` so its `Release` is automatic on scope exit, even on early
//! return / `?` propagation. CoUninitialize fires automatically when ComGuard
//! drops.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::ptr;

use windows_sys::core::HRESULT;
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoUninitialize,
    COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED,
};

pub struct ComGuard { _priv: () }

impl ComGuard {
    pub unsafe fn init_apartment() -> Result<Self, HRESULT> {
        let hr = CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32);
        if hr < 0 { Err(hr) } else { Ok(Self { _priv: () }) }
    }
    pub unsafe fn init_multithreaded() -> Result<Self, HRESULT> {
        let hr = CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32);
        if hr < 0 { Err(hr) } else { Ok(Self { _priv: () }) }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) { unsafe { CoUninitialize(); } }
}

/// Generic IUnknown wrapper. T is expected to begin with the IUnknown vtable.
#[repr(transparent)]
pub struct ComRef<T> { pub ptr: *mut T }

impl<T> ComRef<T> {
    pub fn null() -> Self { Self { ptr: ptr::null_mut() } }
    pub fn from_raw(ptr: *mut T) -> Self { Self { ptr } }
    pub fn as_unknown(&self) -> *mut IUnknown { self.ptr as *mut IUnknown }
    pub fn is_null(&self) -> bool { self.ptr.is_null() }
}

impl<T> Drop for ComRef<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let unk = self.ptr as *mut IUnknown;
                ((*(*unk).vtbl).release)(unk);
            }
        }
    }
}

#[repr(C)]
pub struct IUnknown { pub vtbl: *mut IUnknownVtbl }
#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface: unsafe extern "system" fn(this: *mut IUnknown, riid: *const u8, ppv: *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
    pub release: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
}

/// BSTR RAII guard. windows-sys 0.52 defines BSTR as *const u16.
pub struct Bstr(pub *const u16);
impl Bstr {
    pub fn null() -> Self { Self(ptr::null()) }
    pub fn as_ptr(&self) -> *const u16 { self.0 }
}
impl Drop for Bstr {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                windows_sys::Win32::Foundation::SysFreeString(self.0);
            }
        }
    }
}
