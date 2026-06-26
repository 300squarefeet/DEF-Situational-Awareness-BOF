// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution" },
];

// CLSIDs / IIDs as raw bytes (no plaintext class names)
// CLSID_WbemLocator = {4590f811-1d3a-11d0-891f-00aa004b2e24}
const CLSID_WBEM_LOCATOR: [u8; 16] = [
    0x11, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11,
    0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24,
];
// IID_IWbemLocator = {dc12a687-737f-11cf-884d-00aa004b2e24}
const IID_IWBEM_LOCATOR: [u8; 16] = [
    0x87, 0xa6, 0x12, 0xdc, 0x7f, 0x73, 0xcf, 0x11,
    0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24,
];

// COM vtable slot indices (IWbemLocator, IWbemServices, IEnumWbemClassObject, IWbemClassObject)
// All vtables start at slot 0 = QueryInterface, 1 = AddRef, 2 = Release
// IWbemLocator::ConnectServer = slot 3
// IWbemServices::ExecQuery    = slot 20
// IEnumWbemClassObject::Next  = slot 5
// IWbemClassObject::Get       = slot 4

dfr_fn!(
    co_initialize_ex(reserved: *mut core::ffi::c_void, co_init: u32) -> i32,
    module = "ole32.dll",
    api    = "CoInitializeEx"
);

dfr_fn!(
    co_create_instance(
        rclsid: *const u8,
        p_unk_outer: *mut core::ffi::c_void,
        dw_cls_context: u32,
        riid: *const u8,
        ppv: *mut *mut core::ffi::c_void,
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
    co_set_proxy_blanket(
        proxy: *mut core::ffi::c_void,
        auth_svc: u32, authz_svc: u32,
        server_princ_name: *mut u16,
        authn_level: u32, imp_level: u32,
        auth_info: *mut core::ffi::c_void,
        capabilities: u32,
    ) -> i32,
    module = "ole32.dll",
    api    = "CoSetProxyBlanket"
);

dfr_fn!(
    sys_alloc_string(psz: *const u16) -> *mut u16,
    module = "oleaut32.dll",
    api    = "SysAllocString"
);

dfr_fn!(
    sys_free_string(bstr: *mut u16) -> (),
    module = "oleaut32.dll",
    api    = "SysFreeString"
);

type IUnknownVtbl = [usize; 3];
// For IWbemLocator: vtbl[3] = ConnectServer
// For IWbemServices: vtbl[20] = ExecQuery
// For IEnumWbemClassObject: vtbl[5] = Next
// For IWbemClassObject: vtbl[4] = Get

const CLSCTX_INPROC_SERVER: u32 = 1;
const COINIT_MULTITHREADED: u32 = 0;
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;
const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_NONE: u32 = 0;
const WBEM_FLAG_FORWARD_ONLY: u32 = 0x20;
const WBEM_FLAG_RETURN_IMMEDIATELY: u32 = 0x10;
const WBEM_S_NO_ERROR: i32 = 0;
const WBEM_S_FALSE: i32 = 1;

// Wide WMI namespace + query strings — built from obfuscated ASCII at
// runtime. No plaintext (ASCII or wide-encoded) appears in `.rdata`.
fn build_wide(src: &str, dst: &mut [u16]) -> usize {
    common::str_util::ascii_to_wide_buf(src.as_bytes(), dst)
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Init COM
    unsafe { co_initialize_ex(core::ptr::null_mut(), COINIT_MULTITHREADED) }
        .map_err(|_| "com init")?;

    let mut locator: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_WBEM_LOCATOR.as_ptr(),
            core::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            IID_IWBEM_LOCATOR.as_ptr(),
            &mut locator,
        )
    }.map_err(|_| "create instance")?;
    if hr != 0 || locator.is_null() {
        unsafe { let _ = co_uninitialize(); };
        return Err("loc create failed");
    }

    // Build wide strings from obfuscated ASCII at runtime
    let mut ns_wide = [0u16; 32];
    let _ = build_wide(obf!("\\\\.\\root\\cimv2"), &mut ns_wide);

    // Alloc BSTR for namespace
    let ns_bstr = unsafe { sys_alloc_string(ns_wide.as_ptr()) }
        .map_err(|_| "str alloc resolve")?;
    if ns_bstr.is_null() {
        unsafe { let _ = co_uninitialize(); };
        return Err("ns alloc failed");
    }

    // ConnectServer = IWbemLocator vtbl slot 3
    // ConnectServer(bstrNetworkResource, user, pw, locale, secFlags, authority, ctx, pServices)
    let mut services: *mut core::ffi::c_void = core::ptr::null_mut();
    let vtbl = unsafe { *(locator as *mut *mut usize) };
    let connect_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16, *mut u16, *mut u16, *mut u16,
        i32, *mut u16, *mut core::ffi::c_void, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*vtbl.add(3)) };

    let hr2 = unsafe {
        connect_fn(
            locator, ns_bstr, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
            0, core::ptr::null_mut(), core::ptr::null_mut(), &mut services,
        )
    };
    unsafe { let _ = sys_free_string(ns_bstr); };

    if hr2 != WBEM_S_NO_ERROR || services.is_null() {
        unsafe {
            let release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*vtbl.add(2));
            release(locator);
            let _ = co_uninitialize();
        };
        return Err("svc connect failed");
    }

    // CoSetProxyBlanket
    unsafe {
        let _ = co_set_proxy_blanket(
            services,
            RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
            core::ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            core::ptr::null_mut(), EOAC_NONE,
        );
    };

    // ExecQuery = IWbemServices vtbl slot 20
    let svc_vtbl = unsafe { *(services as *mut *mut usize) };
    let mut wql_wide   = [0u16; 8];
    let mut query_wide = [0u16; 64];
    let _ = build_wide(obf!("WQL"), &mut wql_wide);
    let _ = build_wide(obf!("SELECT Name FROM Win32_Process"), &mut query_wide);

    let wql_bstr = unsafe { sys_alloc_string(wql_wide.as_ptr()) }
        .map_err(|_| "str alloc wql")?;
    let query_bstr = match unsafe { sys_alloc_string(query_wide.as_ptr()) } {
        Ok(p) => p,
        Err(_) => {
            unsafe { let _ = sys_free_string(wql_bstr); };
            return Err("str alloc qry");
        }
    };

    let exec_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16, *mut u16,
        i32, *mut core::ffi::c_void, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(20)) };

    let mut enumerator: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr3 = unsafe {
        exec_fn(
            services,
            wql_bstr, query_bstr,
            (WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY) as i32,
            core::ptr::null_mut(),
            &mut enumerator,
        )
    };

    unsafe {
        let _ = sys_free_string(wql_bstr);
        let _ = sys_free_string(query_bstr);
    };

    if hr3 != WBEM_S_NO_ERROR || enumerator.is_null() {
        unsafe {
            let release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*svc_vtbl.add(2));
            release(services);
            let release_loc: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*vtbl.add(2));
            release_loc(locator);
            let _ = co_uninitialize();
        };
        return Err("query exec failed");
    }

    println!("WMI QUERY: {}", obf!("SELECT Name FROM Win32_Process"));
    println!("{}", "--------------------------------------------");

    let enum_vtbl = unsafe { *(enumerator as *mut *mut usize) };
    // IEnumWbemClassObject::Next = slot 5
    let next_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, i32, u32,
        *mut *mut core::ffi::c_void, *mut u32,
    ) -> i32 = unsafe { core::mem::transmute(*enum_vtbl.add(5)) };

    loop {
        let mut obj: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut returned: u32 = 0;
        let hr_next = unsafe { next_fn(enumerator, -1, 1, &mut obj, &mut returned) };
        if hr_next != WBEM_S_NO_ERROR || returned == 0 || obj.is_null() { break; }

        // IWbemClassObject::Get = slot 4
        let obj_vtbl = unsafe { *(obj as *mut *mut usize) };
        let get_fn: unsafe extern "system" fn(
            *mut core::ffi::c_void, *const u16, i32,
            *mut Variant, *mut i32, *mut i32,
        ) -> i32 = unsafe { core::mem::transmute(*obj_vtbl.add(4)) };

        let mut var = Variant::default();
        let mut prop_wide = [0u16; 16];
        let _ = build_wide(obf!("Name"), &mut prop_wide);
        let hr_get = unsafe { get_fn(obj, prop_wide.as_ptr(), 0, &mut var, core::ptr::null_mut(), core::ptr::null_mut()) };
        if hr_get == 0 && var.vt == 8 /* VT_BSTR */ {
            let bstr = var.bstr_val;
            if !bstr.is_null() {
                let name = wide_to_str(bstr, 128);
                println!("{}", name);
            }
        }
        unsafe {
            let release_obj: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*obj_vtbl.add(2));
            release_obj(obj);
        };
    }

    unsafe {
        let rel_enum: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*enum_vtbl.add(2));
        rel_enum(enumerator);
        let rel_svc: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*svc_vtbl.add(2));
        rel_svc(services);
        let rel_loc: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(*vtbl.add(2));
        rel_loc(locator);
        let _ = co_uninitialize();
    };
    Ok(())
}

#[repr(C)]
struct Variant {
    vt: u16,
    wReserved1: u16,
    wReserved2: u16,
    wReserved3: u16,
    bstr_val: *mut u16,
    // Pad to 24 bytes
    _pad: u64,
}

impl Default for Variant {
    fn default() -> Self {
        Self {
            vt: 0,
            wReserved1: 0,
            wReserved2: 0,
            wReserved3: 0,
            bstr_val: core::ptr::null_mut(),
            _pad: 0,
        }
    }
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
