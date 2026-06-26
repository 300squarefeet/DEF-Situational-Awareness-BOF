// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Start the WebClient service to enable WebDAV on the host.
//!
//! OpenSCManagerA → OpenServiceA("WebClient") → QueryServiceStatusEx →
//! StartServiceA (if not already running) → CloseServiceHandle.
//!
//! Args: none
//!
//! MITRE ATT&CK: T1021.002 (Remote Services: SMB/Windows Admin Shares)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1021.002",
        name: "Remote Services: SMB/Windows Admin Shares",
        tactic: "Lateral Movement",
    },
];

const SC_MANAGER_CONNECT:   u32 = 0x0001;
const SERVICE_START:        u32 = 0x0010;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_RUNNING:      u32 = 4;

/// SERVICE_STATUS_PROCESS — only need dwCurrentState at offset 4 (u32).
/// Full struct is 36 bytes; we read only what we need.
const SERVICE_STATUS_PROCESS_SIZE: u32 = 36;

// SC_STATUS_PROCESS_INFO = 0
const SC_STATUS_PROCESS_INFO: u32 = 0;

dfr_fn!(
    open_sc_manager_a(
        lp_machine_name: *const i8,
        lp_database_name: *const i8,
        dw_desired_access: u32,
    ) -> isize,
    module = "advapi32.dll",
    api    = "OpenSCManagerA"
);

dfr_fn!(
    open_service_a(
        h_sc_manager: isize,
        lp_service_name: *const i8,
        dw_desired_access: u32,
    ) -> isize,
    module = "advapi32.dll",
    api    = "OpenServiceA"
);

dfr_fn!(
    query_service_status_ex(
        h_service: isize,
        info_level: u32,
        lp_buffer: *mut u8,
        cb_buf_size: u32,
        pcb_bytes_needed: *mut u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "QueryServiceStatusEx"
);

dfr_fn!(
    start_service_a(
        h_service: isize,
        dw_num_service_args: u32,
        lp_service_arg_vectors: *const *const i8,
    ) -> i32,
    module = "advapi32.dll",
    api    = "StartServiceA"
);

dfr_fn!(
    close_service_handle(h_sc_object: isize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let hscm = unsafe {
        open_sc_manager_a(
            core::ptr::null(),
            core::ptr::null(),
            SC_MANAGER_CONNECT,
        )
    }.map_err(|_| "resolve failed")?;

    if hscm == 0 {
        return Err("SCM open failed");
    }

    obf! { let svc_name_str = "WebClient"; }
    let mut svc_name_cstr = [0i8; 16];
    for (i, b) in svc_name_str.bytes().enumerate() {
        if i + 1 < svc_name_cstr.len() { svc_name_cstr[i] = b as i8; }
    }

    let hsvc = unsafe {
        open_service_a(
            hscm,
            svc_name_cstr.as_ptr(),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    }.map_err(|_| "resolve failed")?;

    let _ = unsafe { close_service_handle(hscm) };

    if hsvc == 0 {
        return Err("WebClient service not found");
    }

    // Query current state
    let mut status_buf = [0u8; 36];
    let mut bytes_needed: u32 = 0;
    let _ = unsafe {
        query_service_status_ex(
            hsvc,
            SC_STATUS_PROCESS_INFO,
            status_buf.as_mut_ptr(),
            SERVICE_STATUS_PROCESS_SIZE,
            &mut bytes_needed,
        )
    };

    // dwCurrentState is at offset 4 in SERVICE_STATUS (and SERVICE_STATUS_PROCESS)
    let current_state = unsafe {
        core::ptr::read_unaligned(status_buf.as_ptr().add(4) as *const u32)
    };

    if current_state == SERVICE_RUNNING {
        let _ = unsafe { close_service_handle(hsvc) };
        println!("[*] WebClient service is already running");
        return Ok(());
    }

    let rc = unsafe {
        start_service_a(hsvc, 0, core::ptr::null())
    }.map_err(|_| "resolve failed")?;

    let _ = unsafe { close_service_handle(hsvc) };

    if rc == 0 {
        return Err("WebClient service start failed");
    }

    println!("[+] WebClient service started");
    Ok(())
}
