// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Delete a scheduled task via ITaskService COM vtable.
//!
//! ITaskFolder::DeleteTask is at vtable index 13.
//!   DeleteTask(lpTaskName: *const u16, dwFlags: i32) → HRESULT
//!
//! Args: <taskname>
//!
//! MITRE ATT&CK: T1053.005 (Scheduled Task/Job: Scheduled Task)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1053.005",
        name: "Scheduled Task/Job: Scheduled Task",
        tactic: "Defense Evasion",
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
const COINIT_MULTITHREADED:  u32 = 0;
const S_OK: i32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct Variant {
    vt: u16, r1: u16, r2: u16, r3: u16,
    val: u64, _pad: u64,
}
impl Variant {
    fn empty() -> Self { Self { vt: 0, r1: 0, r2: 0, r3: 0, val: 0, _pad: 0 } }
}

dfr_fn!(
    co_initialize_ex(reserved: *mut core::ffi::c_void, co_init: u32) -> i32,
    module = "ole32.dll",
    api    = "CoInitializeEx"
);
dfr_fn!(
    co_create_instance(
        rclsid: *const u8, unk_outer: *mut core::ffi::c_void,
        cls_context: u32, riid: *const u8,
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

const ROOT_W: &[u16] = &[b'\\' as u16, 0];

unsafe fn release_com(vtbl: *mut usize, ptr: *mut core::ffi::c_void) {
    let release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
        core::mem::transmute(*vtbl.add(2));
    release(ptr);
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let taskname = String::from(parser.get_str());
    if taskname.is_empty() {
        return Err("usage: del-task-scheduler <taskname>");
    }
    if taskname.len() > 256 { return Err("taskname too long"); }

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
        return Err("task svc create failed");
    }

    let svc_vtbl = unsafe { *(svc as *mut *mut usize) };

    // Connect — vtable index 3
    let connect_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, Variant, Variant, Variant, Variant,
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(3)) };

    let hr2 = unsafe {
        connect_fn(svc, Variant::empty(), Variant::empty(), Variant::empty(), Variant::empty())
    };
    if hr2 != S_OK {
        unsafe { release_com(svc_vtbl, svc); let _ = co_uninitialize(); };
        return Err("connect failed");
    }

    // GetFolder("\") — vtable index 4
    let get_folder_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(4)) };

    let root_bstr = unsafe { sys_alloc_string(ROOT_W.as_ptr()) }
        .map_err(|_| "bstr alloc")?;
    let mut folder: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr3 = unsafe { get_folder_fn(svc, root_bstr, &mut folder) };
    unsafe { let _ = sys_free_string(root_bstr); };

    if hr3 != S_OK || folder.is_null() {
        unsafe { release_com(svc_vtbl, svc); let _ = co_uninitialize(); };
        return Err("folder get failed");
    }

    let folder_vtbl = unsafe { *(folder as *mut *mut usize) };

    // ITaskFolder::DeleteTask — vtable index 13
    let delete_task_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16, i32,
    ) -> i32 = unsafe { core::mem::transmute(*folder_vtbl.add(13)) };

    // Build BSTR for task name
    let mut name_wide = [0u16; 260];
    common::str_util::ascii_to_wide_buf(taskname.as_bytes(), &mut name_wide);
    let name_bstr = unsafe { sys_alloc_string(name_wide.as_ptr()) }
        .map_err(|_| "bstr alloc")?;

    let hr_del = unsafe { delete_task_fn(folder, name_bstr, 0) };
    unsafe { let _ = sys_free_string(name_bstr); };

    unsafe {
        release_com(folder_vtbl, folder);
        release_com(svc_vtbl, svc);
        let _ = co_uninitialize();
    };

    if hr_del != S_OK {
        return Err("task delete failed");
    }

    println!("[+] scheduled task deleted: {}", taskname);
    Ok(())
}
