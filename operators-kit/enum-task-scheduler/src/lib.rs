// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1053.005",
        name: "Scheduled Task/Job: Scheduled Task",
        tactic: "Execution",
    },
];

// CLSID_TaskScheduler = {0f87369f-a4e5-11d1-9781-00600824309d}
const CLSID_TASK_SCHEDULER: [u8; 16] = [
    0x9f, 0x36, 0x87, 0x0f, 0xe5, 0xa4, 0xd1, 0x11,
    0x97, 0x81, 0x00, 0x60, 0x08, 0x24, 0x30, 0x9d,
];
// IID_ITaskService = {2faba4c7-4da9-4013-9697-20cc3fd40f85}
const IID_ITASK_SERVICE: [u8; 16] = [
    0xc7, 0xa4, 0xab, 0x2f, 0xa9, 0x4d, 0x13, 0x40,
    0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85,
];

const CLSCTX_INPROC_SERVER: u32 = 1;
const COINIT_MULTITHREADED: u32 = 0;
const S_OK: i32 = 0;

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

// Wide string for root folder "\"
const ROOT: &[u16] = &[b'\\' as u16, 0];

#[repr(C)]
#[derive(Clone, Copy)]
struct Variant {
    vt: u16, r1: u16, r2: u16, r3: u16,
    val: u64, _pad: u64,
}
impl Variant {
    fn empty() -> Self { Self { vt: 0, r1: 0, r2: 0, r3: 0, val: 0, _pad: 0 } }
    fn vt_i4(v: i32) -> Self {
        let mut s = Self::empty(); s.vt = 3; s.val = v as u64; s
    }
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
    unsafe { co_initialize_ex(core::ptr::null_mut(), COINIT_MULTITHREADED) }
        .map_err(|_| "com init")?;

    let mut svc: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_TASK_SCHEDULER.as_ptr(),
            core::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            IID_ITASK_SERVICE.as_ptr(),
            &mut svc,
        )
    }.map_err(|_| "create instance")?;

    if hr != S_OK || svc.is_null() {
        unsafe { let _ = co_uninitialize(); };
        return Err("task svc create");
    }

    let svc_vtbl = unsafe { *(svc as *mut *mut usize) };

    let connect_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, Variant, Variant, Variant, Variant,
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(3)) };

    let hr2 = unsafe {
        connect_fn(svc, Variant::empty(), Variant::empty(), Variant::empty(), Variant::empty())
    };
    if hr2 != S_OK {
        unsafe { release_com(svc_vtbl, svc); let _ = co_uninitialize(); };
        return Err("task connect");
    }

    let get_folder_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(4)) };

    let root_bstr = unsafe { sys_alloc_string(ROOT.as_ptr()) }
        .map_err(|_| "str alloc")?;
    let mut folder: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr3 = unsafe { get_folder_fn(svc, root_bstr, &mut folder) };
    unsafe { let _ = sys_free_string(root_bstr); };

    if hr3 != S_OK || folder.is_null() {
        unsafe { release_com(svc_vtbl, svc); let _ = co_uninitialize(); };
        return Err("folder get");
    }

    let folder_vtbl = unsafe { *(folder as *mut *mut usize) };

    let get_tasks_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, i32, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*folder_vtbl.add(8)) };

    let mut tasks: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr4 = unsafe { get_tasks_fn(folder, 0, &mut tasks) };
    if hr4 != S_OK || tasks.is_null() {
        unsafe {
            release_com(folder_vtbl, folder);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        return Err("tasks get");
    }

    let tasks_vtbl = unsafe { *(tasks as *mut *mut usize) };
    let count_fn: unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> i32 =
        unsafe { core::mem::transmute(*tasks_vtbl.add(3)) };
    let mut count: i32 = 0;
    unsafe { count_fn(tasks, &mut count) };

    println!("SCHEDULED TASKS (detailed) — root folder ({} total):", count);
    println!("{}", "--------------------------------------------");

    let item_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, Variant, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*tasks_vtbl.add(4)) };

    for i in 1..=count {
        let mut task: *mut core::ffi::c_void = core::ptr::null_mut();
        let idx_var = Variant::vt_i4(i);
        let hr_item = unsafe { item_fn(tasks, idx_var, &mut task) };
        if hr_item != S_OK || task.is_null() { continue; }

        let task_vtbl = unsafe { *(task as *mut *mut usize) };

        // get_Name — vtable[3]
        let get_name_fn: unsafe extern "system" fn(*mut core::ffi::c_void, *mut *mut u16) -> i32 =
            unsafe { core::mem::transmute(*task_vtbl.add(3)) };
        let mut name_bstr: *mut u16 = core::ptr::null_mut();
        let hr_name = unsafe { get_name_fn(task, &mut name_bstr) };
        let name = if hr_name == S_OK && !name_bstr.is_null() {
            let n = wide_to_str(name_bstr, 128);
            unsafe { let _ = sys_free_string(name_bstr); };
            n
        } else {
            WStr::new()
        };

        // get_Path — vtable[4]
        let get_path_fn: unsafe extern "system" fn(*mut core::ffi::c_void, *mut *mut u16) -> i32 =
            unsafe { core::mem::transmute(*task_vtbl.add(4)) };
        let mut path_bstr: *mut u16 = core::ptr::null_mut();
        let hr_path = unsafe { get_path_fn(task, &mut path_bstr) };
        let path = if hr_path == S_OK && !path_bstr.is_null() {
            let p = wide_to_str(path_bstr, 256);
            unsafe { let _ = sys_free_string(path_bstr); };
            p
        } else {
            WStr::new()
        };

        // get_Enabled — vtable[10]; returns VARIANT_BOOL (i16): -1=enabled, 0=disabled
        let get_enabled_fn: unsafe extern "system" fn(*mut core::ffi::c_void, *mut i16) -> i32 =
            unsafe { core::mem::transmute(*task_vtbl.add(10)) };
        let mut enabled_val: i16 = 0;
        let hr_en = unsafe { get_enabled_fn(task, &mut enabled_val) };
        let state_str = if hr_en == S_OK {
            if enabled_val != 0 { "[enabled]" } else { "[disabled]" }
        } else {
            "[unknown]"
        };

        println!("  {} | path: {} | {}", name, path, state_str);

        unsafe { release_com(task_vtbl, task); };
    }

    unsafe {
        release_com(tasks_vtbl, tasks);
        release_com(folder_vtbl, folder);
        release_com(svc_vtbl, svc);
        let _ = co_uninitialize();
    };
    Ok(())
}

unsafe fn release_com(vtbl: *mut usize, ptr: *mut core::ffi::c_void) {
    let release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
        core::mem::transmute(*vtbl.add(2));
    release(ptr);
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
