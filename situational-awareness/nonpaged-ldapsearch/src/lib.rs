// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1087.002", name: "Domain Account Discovery", tactic: "Discovery" },
];

// ADsGetObject to bind LDAP path via ADSI — stealth: no LDAP connections visible
const S_OK: i32 = 0;
const COINIT_MULTITHREADED: u32 = 0;

// ADSI CLSIDs / IIDs:
// IID_IDirectorySearch = {109ba8ec-92f0-11d0-a790-00c04fd8d5a8}
const IID_IDIRECTORY_SEARCH: [u8; 16] = [
    0xec, 0xa8, 0x9b, 0x10, 0xf0, 0x92, 0xd0, 0x11,
    0xa7, 0x90, 0x00, 0xc0, 0x4f, 0xd8, 0xd5, 0xa8,
];

dfr_fn!(
    co_initialize_ex(reserved: *mut core::ffi::c_void, init: u32) -> i32,
    module = "ole32.dll",
    api    = "CoInitializeEx"
);

dfr_fn!(
    co_uninitialize() -> (),
    module = "ole32.dll",
    api    = "CoUninitialize"
);

dfr_fn!(
    ads_get_object(
        lp_path: *const u16,
        riid: *const u8,
        ppv_obj: *mut *mut core::ffi::c_void,
    ) -> i32,
    module = "activeds.dll",
    api    = "ADsGetObject"
);

dfr_fn!(
    sys_free_string(bstr: *mut u16) -> (),
    module = "oleaut32.dll",
    api    = "SysFreeString"
);

dfr_fn!(
    sys_alloc_string(s: *const u16) -> *mut u16,
    module = "oleaut32.dll",
    api    = "SysAllocString"
);

// LDAP path: "LDAP://rootDSE"
const LDAP_ROOTDSE: &[u16] = &[
    b'L' as u16, b'D' as u16, b'A' as u16, b'P' as u16, b':' as u16,
    b'/' as u16, b'/' as u16,
    b'r' as u16, b'o' as u16, b'o' as u16, b't' as u16, b'D' as u16, b'S' as u16, b'E' as u16,
    0,
];

// IDirectorySearch vtable:
// 0=QI, 1=AddRef, 2=Release, 3=SetSearchPreference, 4=ExecuteSearch, 5=AbandonSearch,
// 6=GetFirstRow, 7=GetNextRow, 8=GetPreviousRow, 9=GetNextColumnName,
// 10=GetColumn, 11=FreeColumn, 12=CloseSearchHandle

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    unsafe { co_initialize_ex(core::ptr::null_mut(), COINIT_MULTITHREADED) }
        .map_err(|_| "resolve")?;

    let mut ds: *mut core::ffi::c_void = core::ptr::null_mut();

    // Bind to LDAP://rootDSE first to get default naming context, then
    // re-bind to LDAP:///<defaultNamingContext> for user search.
    // For simplicity, bind directly to LDAP:// (empty = default DC)
    const LDAP_ALL: &[u16] = &[
        b'L' as u16, b'D' as u16, b'A' as u16, b'P' as u16, b':' as u16,
        b'/' as u16, b'/' as u16, 0,
    ];

    let hr = unsafe {
        ads_get_object(
            LDAP_ALL.as_ptr(),
            IID_IDIRECTORY_SEARCH.as_ptr(),
            &mut ds,
        )
    }.map_err(|_| "resolve failed")?;

    if hr != S_OK || ds.is_null() {
        unsafe { let _ = co_uninitialize(); };
        // Not a domain-joined host or activeds.dll not available
        println!("[*] obj get failed — host may not be domain-joined");
        return Ok(());
    }

    let vtbl = unsafe { *(ds as *mut *mut usize) };

    // ADS_SEARCHPREF_INFO for non-paged (size limit = 0 means unlimited paged, but
    // we want non-paged: set ADS_SEARCHPREF_SIZE_LIMIT to a large value, paging off)
    // SetSearchPreference = vtbl[3]
    // We skip SetSearchPreference for now and use defaults (already non-paged by default in ADSI)

    // ExecuteSearch = vtbl[4]
    // ADS_SEARCH_HANDLE is just *mut c_void returned
    let filter_wide: &[u16] = &[
        b'(' as u16, b'o' as u16, b'b' as u16, b'j' as u16, b'e' as u16,
        b'c' as u16, b't' as u16, b'C' as u16, b'l' as u16, b'a' as u16,
        b's' as u16, b's' as u16, b'=' as u16,
        b'u' as u16, b's' as u16, b'e' as u16, b'r' as u16,
        b')' as u16, 0,
    ];

    let exec_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *const u16, // filter
        *mut *const u16, // attrs (NULL = all)
        u32,         // dwNumberAttributes
        *mut usize,  // phSearchResult
    ) -> i32 = unsafe { core::mem::transmute(*vtbl.add(4)) };

    let mut search_handle: usize = 0;
    let hr2 = unsafe {
        exec_fn(ds, filter_wide.as_ptr(), core::ptr::null_mut(), 0xFFFFFFFF, &mut search_handle)
    };

    if hr2 != S_OK {
        unsafe {
            let rel: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*vtbl.add(2));
            rel(ds);
            let _ = co_uninitialize();
        };
        return Err("search failed");
    }

    println!("LDAP USER SEARCH (non-paged via ADSI):");
    println!("{}", "--------------------------------------------");

    // GetFirstRow = vtbl[6], GetNextRow = vtbl[7]
    let get_first_fn: unsafe extern "system" fn(*mut core::ffi::c_void, usize) -> i32 =
        unsafe { core::mem::transmute(*vtbl.add(6)) };
    let get_next_fn: unsafe extern "system" fn(*mut core::ffi::c_void, usize) -> i32 =
        unsafe { core::mem::transmute(*vtbl.add(7)) };
    let get_next_col_fn: unsafe extern "system" fn(*mut core::ffi::c_void, usize, *mut *mut u16) -> i32 =
        unsafe { core::mem::transmute(*vtbl.add(9)) };

    let S_ADS_NOMORE_ROWS: i32 = 0x00005012u32 as i32;

    let mut hr_row = unsafe { get_first_fn(ds, search_handle) };
    while hr_row != S_ADS_NOMORE_ROWS && hr_row == S_OK {
        // Print column names for each row
        let mut col_name: *mut u16 = core::ptr::null_mut();
        loop {
            let hr_col = unsafe { get_next_col_fn(ds, search_handle, &mut col_name) };
            if hr_col != S_OK { break; }
            if !col_name.is_null() {
                let s = wide_to_str(col_name, 64);
                rustbof::print!(" {}  ", s);
                unsafe { let _ = sys_free_string(col_name); };
            }
        }
        println!("");
        hr_row = unsafe { get_next_fn(ds, search_handle) };
    }

    // CloseSearchHandle = vtbl[12]
    let close_fn: unsafe extern "system" fn(*mut core::ffi::c_void, usize) -> i32 =
        unsafe { core::mem::transmute(*vtbl.add(12)) };
    unsafe { close_fn(ds, search_handle) };

    unsafe {
        let rel: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*vtbl.add(2));
        rel(ds);
        let _ = co_uninitialize();
    };
    Ok(())
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let wc = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if wc == 0 { break; }
        s.push(if wc < 128 { wc as u8 } else { b'?' });
    }
    s
}

struct WStr { buf: [u8; 128], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 128], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
