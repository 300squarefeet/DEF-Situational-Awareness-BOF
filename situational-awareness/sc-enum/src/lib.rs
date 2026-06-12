// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Enumerate all services via EnumServicesStatusExA.
//! Args: (none)
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1007", name: "System Service Discovery", tactic: "Discovery" },
];

const SC_MANAGER_CONNECT: u32    = 0x0001;
const SC_MANAGER_ENUMERATE: u32  = 0x0004;
const SERVICE_WIN32: u32         = 0x30;
const SERVICE_STATE_ALL: u32     = 0x3;
const SC_ENUM_PROCESS_INFO: u32  = 0;

// ENUM_SERVICE_STATUS_PROCESSA layout (x64):
//   *i8  lpServiceName   @ offset 0   (8 bytes)
//   *i8  lpDisplayName   @ offset 8   (8 bytes)
//   SERVICE_STATUS_PROCESS starts @ offset 16:
//     u32 dwServiceType       @ +0
//     u32 dwCurrentState      @ +4
//     u32 dwControlsAccepted  @ +8
//     u32 dwWin32ExitCode     @ +12
//     u32 dwServiceSpecific   @ +16
//     u32 dwCheckPoint        @ +20
//     u32 dwWaitHint          @ +24
//     u32 dwProcessId         @ +28
//     u32 dwServiceFlags      @ +32

dfr_fn!(
    open_sc_manager_a(
        lp_machine_name: *const i8,
        lp_database_name: *const i8,
        dw_desired_access: u32,
    ) -> *mut core::ffi::c_void,
    module = "advapi32.dll",
    api    = "OpenSCManagerA"
);

dfr_fn!(
    enum_services_status_ex_a(
        h_sc_manager: *mut core::ffi::c_void,
        info_level: u32,
        dw_service_type: u32,
        dw_service_state: u32,
        lp_services: *mut u8,
        cb_buf_size: u32,
        pcb_bytes_needed: *mut u32,
        lp_services_returned: *mut u32,
        lp_resume_handle: *mut u32,
        psz_group_name: *const i8,
    ) -> i32,
    module = "advapi32.dll",
    api    = "EnumServicesStatusExA"
);

dfr_fn!(
    close_service_handle(h_sc_object: *mut core::ffi::c_void) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let h_scm = unsafe {
        open_sc_manager_a(
            core::ptr::null(),
            core::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE,
        )
    }.map_err(|_| "open failed")?;

    if h_scm.is_null() {
        return Err("open failed");
    }

    // First call to get required buffer size
    let mut bytes_needed: u32 = 0;
    let mut services_returned: u32 = 0;
    let mut resume_handle: u32 = 0;

    let _ = unsafe {
        enum_services_status_ex_a(
            h_scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            core::ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            core::ptr::null(),
        )
    };

    let buf_size = if bytes_needed == 0 { 65536 } else { bytes_needed };
    let mut buf: Vec<u8> = alloc::vec![0u8; buf_size as usize];
    resume_handle = 0;

    let ok = unsafe {
        enum_services_status_ex_a(
            h_scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            core::ptr::null(),
        )
    }.unwrap_or(0);

    unsafe { let _ = close_service_handle(h_scm); };

    if ok == 0 && services_returned == 0 {
        return Err("enum failed");
    }

    println!("Services ({} total):", services_returned);
    println!("{:<40} {:<40} {:<12} {}", "ServiceName", "DisplayName", "State", "PID");
    println!("{}", "-".repeat(100));

    // ENUM_SERVICE_STATUS_PROCESSA record stride on x64 = 72 bytes
    // (8 + 8 pointer fields + 36-byte SERVICE_STATUS_PROCESS, padded to 72)
    // In practice each record is exactly 2 pointers + 9 DWORDs = 16+36 = 52 bytes,
    // but the struct is padded to pointer-alignment: 8+8+4*9 = 52, rounded to 56 on x64.
    // The actual layout returned by Windows is a flat array; pointers point into the
    // same buffer. We use the documented field offsets.
    const RECORD_SIZE: usize = 56; // sizeof(ENUM_SERVICE_STATUS_PROCESSA) x64

    for i in 0..services_returned as usize {
        let base = buf.as_ptr().wrapping_add(i * RECORD_SIZE);
        let name_ptr   = unsafe { core::ptr::read_unaligned(base as *const *const i8) };
        let disp_ptr   = unsafe { core::ptr::read_unaligned(base.add(8) as *const *const i8) };
        // SERVICE_STATUS_PROCESS starts at offset 16
        let state      = unsafe { core::ptr::read_unaligned(base.add(16 + 4) as *const u32) };
        let pid        = unsafe { core::ptr::read_unaligned(base.add(16 + 28) as *const u32) };

        let name = ptr_to_cstr(name_ptr as *const u8, 256);
        let disp = ptr_to_cstr(disp_ptr as *const u8, 256);
        println!("{:<40} {:<40} {:<12} {}", name, disp, svc_state(state), pid);
    }

    Ok(())
}

fn svc_state(s: u32) -> &'static str {
    match s {
        1 => "STOPPED", 2 => "START_PENDING", 3 => "STOP_PENDING",
        4 => "RUNNING", 5 => "CONTINUE_PENDING", 6 => "PAUSE_PENDING",
        7 => "PAUSED", _ => "UNKNOWN",
    }
}

fn ptr_to_cstr(p: *const u8, max: usize) -> CStr {
    let mut s = CStr::new();
    if p.is_null() { return s; }
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(p.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

struct CStr { buf: [u8; 512], len: usize }
impl CStr {
    fn new() -> Self { Self { buf: [0u8; 512], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for CStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
