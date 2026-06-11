// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
// Original C: TrustedSec/cs-remote-ops/sc_delete
//
//! Stop + delete a Windows service.
//! Args: <target-UNC|''> <svc-name>

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1489", name: "Service Stop", tactic: "Impact" },
];

const SC_MANAGER_CONNECT:    u32 = 0x0001;
const SERVICE_STOP:          u32 = 0x0020;
const SERVICE_DELETE:        u32 = 0x10000;
const SERVICE_QUERY_STATUS:  u32 = 0x0004;
const SERVICE_CONTROL_STOP:  u32 = 0x00000001;

#[repr(C)]
struct ServiceStatus {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
}

dfr_fn!(
    open_sc_manager_a(machine: *const i8, db: *const i8, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenSCManagerA"
);

dfr_fn!(
    open_service_a(scm: usize, svc: *const i8, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenServiceA"
);

dfr_fn!(
    control_service(svc: usize, control: u32, status: *mut ServiceStatus) -> i32,
    module = "advapi32.dll",
    api    = "ControlService"
);

dfr_fn!(
    delete_service(svc: usize) -> i32,
    module = "advapi32.dll",
    api    = "DeleteService"
);

dfr_fn!(
    close_service_handle(h: usize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let target = String::from(parser.get_str());
    let svc    = String::from(parser.get_str());
    let target = target.as_str();
    let svc    = svc.as_str();

    if svc.is_empty() {
        return Err("usage: sc-delete <\\\\host|''> <svc-name>");
    }

    let mut target_buf = [0u8; 256];
    let mut svc_buf    = [0u8; 256];

    let target_ptr = if target.is_empty() {
        core::ptr::null()
    } else {
        if target.len() >= target_buf.len() - 1 { return Err("target too long"); }
        target_buf[..target.len()].copy_from_slice(target.as_bytes());
        target_buf.as_ptr() as *const i8
    };
    if svc.len() >= svc_buf.len() - 1 { return Err("svc name too long"); }
    svc_buf[..svc.len()].copy_from_slice(svc.as_bytes());

    let scm = unsafe { open_sc_manager_a(target_ptr, core::ptr::null(), SC_MANAGER_CONNECT) }
        .map_err(|_| "OpenSCManagerA resolve")?;
    if scm == 0 { return Err("OpenSCManagerA failed"); }

    let h_svc = unsafe {
        open_service_a(scm, svc_buf.as_ptr() as *const i8,
            SERVICE_STOP | SERVICE_DELETE | SERVICE_QUERY_STATUS)
    }.map_err(|_| "OpenServiceA resolve")?;
    if h_svc == 0 {
        unsafe { let _ = close_service_handle(scm); };
        return Err("OpenServiceA failed (svc not found / no access)");
    }

    // Best-effort stop. Ignore errors — service may already be stopped.
    let mut status: ServiceStatus = unsafe { core::mem::zeroed() };
    let _ = unsafe { control_service(h_svc, SERVICE_CONTROL_STOP, &mut status) };

    let deleted = unsafe { delete_service(h_svc) }.map_err(|_| "DeleteService resolve")?;

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(scm);
    };

    if deleted == 0 { return Err("DeleteService failed"); }
    obf! { let ok = "service deleted"; }
    println!("[+] {} ({})", ok, svc);
    Ok(())
}
