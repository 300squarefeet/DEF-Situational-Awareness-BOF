// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
];

// CLSID_CCertConfig = {372fce38-4324-11d0-8810-00a0c903b83c}
const CLSID_CCERT_CONFIG: [u8; 16] = [
    0x38, 0xce, 0x2f, 0x37, 0x24, 0x43, 0xd0, 0x11,
    0x88, 0x10, 0x00, 0xa0, 0xc9, 0x03, 0xb8, 0x3c,
];
// IID_ICertConfig = {372fce34-4324-11d0-8810-00a0c903b83c}
const IID_ICERT_CONFIG: [u8; 16] = [
    0x34, 0xce, 0x2f, 0x37, 0x24, 0x43, 0xd0, 0x11,
    0x88, 0x10, 0x00, 0xa0, 0xc9, 0x03, 0xb8, 0x3c,
];

const CLSCTX_INPROC_SERVER: u32 = 1;
const COINIT_MULTITHREADED: u32 = 0;
const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const CC_FIRSTCONFIG: i32 = 0;
const CC_DEFAULTCONFIG: i32 = -1;
const CC_UIPICKCONFIG: i32 = -2;

dfr_fn!(
    co_initialize_ex(reserved: *mut core::ffi::c_void, init: u32) -> i32,
    module = "ole32.dll",
    api    = "CoInitializeEx"
);

dfr_fn!(
    co_create_instance(
        rclsid: *const u8, unk: *mut core::ffi::c_void, ctx: u32,
        riid: *const u8, ppv: *mut *mut core::ffi::c_void,
    ) -> i32,
    module = "ole32.dll",
    api    = "CoCreateInstance"
);

dfr_fn!(
    co_uninitialize() -> (),
    module = "ole32.dll",
    api    = "CoUninitialize"
);

dfr_fn!(
    sys_free_string(bstr: *mut u16) -> (),
    module = "oleaut32.dll",
    api    = "SysFreeString"
);

// ICertConfig vtable:
// 0=QI, 1=AddRef, 2=Release, 3=GetTypeInfoCount, 4=GetTypeInfo, 5=GetIDsOfNames,
// 6=Invoke, 7=Reset, 8=Next, 9=GetField, 10=GetConfig
// Since it's IDispatch-derived (dual interface), COM vtable base is at 7+

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
        .map_err(|_| "com init")?;

    let mut cfg: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_CCERT_CONFIG.as_ptr(),
            core::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            IID_ICERT_CONFIG.as_ptr(),
            &mut cfg,
        )
    }.map_err(|_| "create instance")?;

    if hr != S_OK || cfg.is_null() {
        unsafe { let _ = co_uninitialize(); };
        println!("[*] ICertConfig not available — ADCS may not be installed");
        return Ok(());
    }

    let vtbl = unsafe { *(cfg as *mut *mut usize) };

    // ICertConfig::Reset = vtbl[7]
    let reset_fn: unsafe extern "system" fn(*mut core::ffi::c_void, i32, *mut i32) -> i32 =
        unsafe { core::mem::transmute(*vtbl.add(7)) };

    // ICertConfig::Next = vtbl[8]
    let next_fn: unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> i32 =
        unsafe { core::mem::transmute(*vtbl.add(8)) };

    // ICertConfig::GetField = vtbl[9]
    let get_field_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16, *mut *mut u16,
    ) -> i32 = unsafe { core::mem::transmute(*vtbl.add(9)) };

    let mut count: i32 = 0;
    let hr2 = unsafe { reset_fn(cfg, CC_FIRSTCONFIG, &mut count) };
    if hr2 != S_OK {
        unsafe {
            let rel: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*vtbl.add(2));
            rel(cfg);
            let _ = co_uninitialize();
        };
        println!("[*] No CA configurations found");
        return Ok(());
    }

    println!("ADCS CA CONFIGURATIONS ({}):", count);
    println!("{}", "--------------------------------------------");

    // Field names — built from obfuscated ASCII at runtime, never plaintext in .rdata
    let mut fld_ca = [0u16; 8];
    let mut fld_server = [0u16; 16];
    common::str_util::ascii_to_wide_buf(obf!("CA").as_bytes(), &mut fld_ca);
    common::str_util::ascii_to_wide_buf(obf!("Server").as_bytes(), &mut fld_server);

    loop {
        let mut index: i32 = 0;
        let hr_next = unsafe { next_fn(cfg, &mut index) };
        if hr_next == S_FALSE { break; }
        if hr_next != S_OK { break; }

        let ca_name   = get_field_bstr(get_field_fn, cfg, fld_ca.as_ptr() as *mut u16);
        let server    = get_field_bstr(get_field_fn, cfg, fld_server.as_ptr() as *mut u16);
        println!("  CA:     {}", ca_name);
        println!("  Server: {}", server);
        println!("");

        if let Some(bstr) = ca_name.bstr { unsafe { let _ = sys_free_string(bstr); }; }
        if let Some(bstr) = server.bstr { unsafe { let _ = sys_free_string(bstr); }; }
    }

    unsafe {
        let rel: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*vtbl.add(2));
        rel(cfg);
        let _ = co_uninitialize();
    };
    Ok(())
}

fn get_field_bstr(
    get_field_fn: unsafe extern "system" fn(*mut core::ffi::c_void, *mut u16, *mut *mut u16) -> i32,
    obj: *mut core::ffi::c_void,
    field: *mut u16,
) -> BstrResult {
    let mut bstr: *mut u16 = core::ptr::null_mut();
    let hr = unsafe { get_field_fn(obj, field, &mut bstr) };
    if hr == 0 && !bstr.is_null() {
        BstrResult { bstr: Some(bstr), s: wide_to_str(bstr, 128) }
    } else {
        BstrResult { bstr: None, s: wide_to_str(core::ptr::null(), 0) }
    }
}

struct BstrResult { bstr: Option<*mut u16>, s: WStr }
impl core::fmt::Display for BstrResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.s.fmt(f)
    }
}

fn wide_to_str(ptr: *const u16, max: usize) -> WStr {
    let mut s = WStr::new();
    if ptr.is_null() { for b in b"(null)" { s.push(*b); } return s; }
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
