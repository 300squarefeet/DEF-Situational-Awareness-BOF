// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
];

// CLSID_WbemLocator = {4590F811-1D3A-11D0-891F-00AA004B2E24}
const CLSID_WBEM_LOCATOR: [u8; 16] = [
    0x11, 0xF8, 0x90, 0x45, 0x3A, 0x1D, 0xD0, 0x11,
    0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24,
];
// IID_IWbemLocator = {DC12A687-737F-11CF-884D-00AA004B2E24}
const IID_IWBEM_LOCATOR: [u8; 16] = [
    0x87, 0xA6, 0x12, 0xDC, 0x7F, 0x73, 0xCF, 0x11,
    0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24,
];

// WMI namespace: ROOT\CIMV2
const NAMESPACE: &[u16] = &[
    b'R' as u16, b'O' as u16, b'O' as u16, b'T' as u16,
    b'\\' as u16,
    b'C' as u16, b'I' as u16, b'M' as u16, b'V' as u16, b'2' as u16,
    0,
];

// WQL query: SELECT * FROM Win32_ShadowCopy
const QUERY: &[u16] = &[
    b'S' as u16, b'E' as u16, b'L' as u16, b'E' as u16, b'C' as u16, b'T' as u16,
    b' ' as u16, b'*' as u16, b' ' as u16,
    b'F' as u16, b'R' as u16, b'O' as u16, b'M' as u16, b' ' as u16,
    b'W' as u16, b'i' as u16, b'n' as u16, b'3' as u16, b'2' as u16,
    b'_' as u16,
    b'S' as u16, b'h' as u16, b'a' as u16, b'd' as u16, b'o' as u16, b'w' as u16,
    b'C' as u16, b'o' as u16, b'p' as u16, b'y' as u16,
    0,
];

// WQL language string
const WQL: &[u16] = &[b'W' as u16, b'Q' as u16, b'L' as u16, 0];

// Property names
const PROP_ID: &[u16] = &[b'I' as u16, b'D' as u16, 0];
const PROP_VOLUME: &[u16] = &[
    b'V' as u16, b'o' as u16, b'l' as u16, b'u' as u16, b'm' as u16,
    b'e' as u16, b'N' as u16, b'a' as u16, b'm' as u16, b'e' as u16,
    0,
];

dfr_fn!(
    co_initialize_ex(reserved: *mut core::ffi::c_void, co_init: u32) -> i32,
    module = "ole32.dll",
    api    = "CoInitializeEx"
);

dfr_fn!(
    co_create_instance(
        rclsid: *const u8,
        unk_outer: *mut core::ffi::c_void,
        cls_context: u32,
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
    sys_alloc_string(s: *const u16) -> *mut u16,
    module = "oleaut32.dll",
    api    = "SysAllocString"
);

dfr_fn!(
    sys_free_string(bstr: *mut u16) -> (),
    module = "oleaut32.dll",
    api    = "SysFreeString"
);

#[repr(C)]
#[derive(Clone, Copy)]
struct Variant {
    vt: u16, r1: u16, r2: u16, r3: u16,
    val: u64, _pad: u64,
}
impl Variant {
    fn empty() -> Self { Self { vt: 0, r1: 0, r2: 0, r3: 0, val: 0, _pad: 0 } }
}

struct WStr { buf: [u8; 256], len: usize }
impl WStr {
    fn new() -> Self { Self { buf: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for WStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
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

unsafe fn release_com(vtbl: *mut usize, ptr: *mut core::ffi::c_void) {
    let release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
        core::mem::transmute(*vtbl.add(2));
    release(ptr);
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
    // CoInitializeEx — COINIT_MULTITHREADED = 0
    unsafe { co_initialize_ex(core::ptr::null_mut(), 0) }.map_err(|_| "com init")?;

    // CoCreateInstance — CLSCTX_INPROC_SERVER = 1
    let mut locator: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_WBEM_LOCATOR.as_ptr(),
            core::ptr::null_mut(),
            1u32,
            IID_IWBEM_LOCATOR.as_ptr(),
            &mut locator,
        )
    }.map_err(|_| "create failed")?;

    if hr != 0 || locator.is_null() {
        unsafe { let _ = co_uninitialize(); };
        return Err("locator failed");
    }

    let loc_vtbl = unsafe { *(locator as *mut *mut usize) };

    // IWbemLocator::ConnectServer at vtbl[3]
    let connect_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u16,                    // strNetworkResource (BSTR)
        *mut u16,                    // strUser
        *mut u16,                    // strPassword
        *mut u16,                    // strLocale
        i32,                         // lSecurityFlags
        *mut u16,                    // strAuthority
        *mut core::ffi::c_void,      // pCtx
        *mut *mut core::ffi::c_void, // ppNamespace -> IWbemServices
    ) -> i32 = unsafe { core::mem::transmute(*loc_vtbl.add(3)) };

    let ns_bstr = unsafe { sys_alloc_string(NAMESPACE.as_ptr()) }
        .map_err(|_| "str alloc")?;
    if ns_bstr.is_null() {
        unsafe { release_com(loc_vtbl, locator); let _ = co_uninitialize(); };
        return Err("str alloc");
    }

    let mut services: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr2 = unsafe {
        connect_fn(
            locator, ns_bstr,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
            0,
            core::ptr::null_mut(), core::ptr::null_mut(),
            &mut services,
        )
    };
    unsafe { let _ = sys_free_string(ns_bstr); };

    if hr2 != 0 || services.is_null() {
        unsafe { release_com(loc_vtbl, locator); let _ = co_uninitialize(); };
        return Err("connect failed");
    }

    let svc_vtbl = unsafe { *(services as *mut *mut usize) };

    // IWbemServices::ExecQuery at vtbl[20]
    // WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY = 0x20 | 0x10 = 0x30
    let exec_query_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u16,                    // strQueryLanguage (BSTR)
        *mut u16,                    // strQuery (BSTR)
        i32,                         // lFlags
        *mut core::ffi::c_void,      // pCtx
        *mut *mut core::ffi::c_void, // ppEnum
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(20)) };

    let wql_bstr = unsafe { sys_alloc_string(WQL.as_ptr()) }
        .map_err(|_| "str alloc")?;
    if wql_bstr.is_null() {
        unsafe { release_com(svc_vtbl, services); release_com(loc_vtbl, locator); let _ = co_uninitialize(); };
        return Err("str alloc");
    }
    let query_bstr = unsafe { sys_alloc_string(QUERY.as_ptr()) }
        .map_err(|_| "str alloc")?;
    if query_bstr.is_null() {
        unsafe {
            let _ = sys_free_string(wql_bstr);
            release_com(svc_vtbl, services);
            release_com(loc_vtbl, locator);
            let _ = co_uninitialize();
        };
        return Err("str alloc");
    }

    let mut p_enum: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr3 = unsafe {
        exec_query_fn(services, wql_bstr, query_bstr, 0x30i32, core::ptr::null_mut(), &mut p_enum)
    };
    unsafe {
        let _ = sys_free_string(wql_bstr);
        let _ = sys_free_string(query_bstr);
    };

    if hr3 != 0 || p_enum.is_null() {
        unsafe {
            release_com(svc_vtbl, services);
            release_com(loc_vtbl, locator);
            let _ = co_uninitialize();
        };
        return Err("query failed");
    }

    let enum_vtbl = unsafe { *(p_enum as *mut *mut usize) };

    // IEnumWbemClassObject::Next at vtbl[4]
    let next_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        u32,                         // lTimeout (WBEM_INFINITE = 0xFFFFFFFF)
        u32,                         // uCount
        *mut *mut core::ffi::c_void, // ppObjects
        *mut u32,                    // puReturned
    ) -> i32 = unsafe { core::mem::transmute(*enum_vtbl.add(4)) };

    println!("Volume Shadow Copies:");

    let mut found = false;
    loop {
        let mut obj: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut returned: u32 = 0;
        let hr_next = unsafe { next_fn(p_enum, 0xFFFFFFFFu32, 1, &mut obj, &mut returned) };
        if hr_next != 0 || returned == 0 || obj.is_null() { break; }

        let obj_vtbl = unsafe { *(obj as *mut *mut usize) };

        // IWbemClassObject::Get at vtbl[4]
        let get_fn: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const u16,     // wszName
            i32,            // lFlags
            *mut Variant,   // pVal
            *mut i32,       // pType
            *mut i32,       // plFlavor
        ) -> i32 = unsafe { core::mem::transmute(*obj_vtbl.add(4)) };

        // Get ID property
        let mut var_id = Variant::empty();
        let hr_id = unsafe {
            get_fn(obj, PROP_ID.as_ptr(), 0, &mut var_id, core::ptr::null_mut(), core::ptr::null_mut())
        };

        // Get VolumeName property
        let mut var_vol = Variant::empty();
        let hr_vol = unsafe {
            get_fn(obj, PROP_VOLUME.as_ptr(), 0, &mut var_vol, core::ptr::null_mut(), core::ptr::null_mut())
        };

        // vt==8 means BSTR — pointer stored in val as usize
        if hr_id == 0 && var_id.vt == 8 {
            let id_str = wide_to_str(var_id.val as *const u16, 256);
            if hr_vol == 0 && var_vol.vt == 8 {
                let vol_str = wide_to_str(var_vol.val as *const u16, 256);
                println!("  ID={} Volume={}", id_str, vol_str);
            } else {
                println!("  ID={}", id_str);
            }
            found = true;
        }

        unsafe { release_com(obj_vtbl, obj); };
    }

    if !found {
        println!("[*] No volume shadow copies found.");
    }

    unsafe {
        release_com(enum_vtbl, p_enum);
        release_com(svc_vtbl, services);
        release_com(loc_vtbl, locator);
        let _ = co_uninitialize();
    };
    Ok(())
}
