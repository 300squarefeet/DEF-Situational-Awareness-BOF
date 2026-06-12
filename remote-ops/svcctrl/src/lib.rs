// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Generic service controller: start / stop / pause / continue a named service.
//! Args: <servicename> <action>
//!   action = "start" | "stop" | "pause" | "continue"
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1489",     name: "Service Stop",      tactic: "Impact"    },
    Technique { id: "T1569.002", name: "Service Execution", tactic: "Execution" },
];

const SC_MANAGER_CONNECT:    u32 = 0x0001;
const SERVICE_START:         u32 = 0x0010;
const SERVICE_STOP:          u32 = 0x0020;
const SERVICE_PAUSE_CONTINUE:u32 = 0x0040;

const SERVICE_CONTROL_STOP:     u32 = 1;
const SERVICE_CONTROL_PAUSE:    u32 = 2;
const SERVICE_CONTROL_CONTINUE: u32 = 3;

dfr_fn!(
    open_sc_manager_a(machine: *const i8, db: *const i8, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenSCManagerA"
);

dfr_fn!(
    open_service_a(scm: usize, name: *const i8, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenServiceA"
);

dfr_fn!(
    start_service_a(svc: usize, argc: u32, argv: *const *const i8) -> i32,
    module = "advapi32.dll",
    api    = "StartServiceA"
);

dfr_fn!(
    control_service(svc: usize, control: u32, status: *mut u8) -> i32,
    module = "advapi32.dll",
    api    = "ControlService"
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
    let svc_s    = String::from(parser.get_str());
    let action_s = String::from(parser.get_str());
    let svc    = svc_s.as_str();
    let action = action_s.as_str();

    if svc.is_empty() || action.is_empty() {
        return Err("usage: svcctrl <service> <start|stop|pause|continue>");
    }

    let mut svc_buf = [0u8; 256];
    if svc.len() >= svc_buf.len() - 1 { return Err("svc name too long"); }
    svc_buf[..svc.len()].copy_from_slice(svc.as_bytes());

    // Open SCM
    let scm = unsafe {
        open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT)
    }.map_err(|_| "scm resolve")?;
    if scm == 0 { return Err("scm open failed"); }

    // Determine required access
    let access = match action {
        "start"    => SERVICE_START,
        "stop"     => SERVICE_STOP,
        "pause"    | "continue" => SERVICE_PAUSE_CONTINUE,
        _ => {
            unsafe { let _ = close_service_handle(scm); };
            return Err("action must be: start stop pause continue");
        }
    };

    let h_svc = unsafe {
        open_service_a(scm, svc_buf.as_ptr() as *const i8, access)
    }.map_err(|_| "svc open resolve")?;
    if h_svc == 0 {
        unsafe { let _ = close_service_handle(scm); };
        return Err("service open failed");
    }

    let rc = match action {
        "start" => unsafe {
            start_service_a(h_svc, 0, core::ptr::null())
        }.map_err(|_| "start resolve")?,
        _ => {
            let ctrl = match action {
                "stop"     => SERVICE_CONTROL_STOP,
                "pause"    => SERVICE_CONTROL_PAUSE,
                "continue" => SERVICE_CONTROL_CONTINUE,
                _          => SERVICE_CONTROL_STOP,
            };
            let mut status_buf = [0u8; 28];
            unsafe {
                control_service(h_svc, ctrl, status_buf.as_mut_ptr())
            }.map_err(|_| "control resolve")?
        }
    };

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(scm);
    };

    obf! { let ok = "service action done"; }
    println!("[+] {} ({}) rc={}", ok, svc, rc);
    Ok(())
}
