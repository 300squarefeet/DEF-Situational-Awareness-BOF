// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Start a service via StartServiceA.
//! Args: <servicename>
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1569.002", name: "Service Execution", tactic: "Execution" },
];

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_START:      u32 = 0x0010;

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
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let svc_name = String::from(parser.get_str());
    let svc_name = svc_name.as_str();
    if svc_name.is_empty() {
        return Err("usage: sc-start <svc>");
    }

    let mut svc_buf = [0u8; 256];
    if svc_name.len() >= svc_buf.len() - 1 { return Err("svc name too long"); }
    svc_buf[..svc_name.len()].copy_from_slice(svc_name.as_bytes());

    let scm = unsafe { open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT) }
        .map_err(|_| "open scm resolve")?;
    if scm == 0 { return Err("open scm failed"); }

    let h_svc = unsafe { open_service_a(scm, svc_buf.as_ptr() as *const i8, SERVICE_START) }
        .map_err(|_| "open svc resolve")?;
    if h_svc == 0 {
        unsafe { let _ = close_service_handle(scm); };
        return Err("open service failed");
    }

    let rc = unsafe { start_service_a(h_svc, 0, core::ptr::null()) }
        .map_err(|_| "start resolve")?;

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(scm);
    };

    if rc == 0 { return Err("start failed"); }
    obf! { let ok = "service started"; }
    println!("[+] {} ({})", ok, svc_name);
    Ok(())
}
