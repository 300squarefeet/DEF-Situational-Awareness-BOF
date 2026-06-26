// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Set service failure actions (restart after delay).
//! Args: <servicename> [delay_ms]
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1543.003", name: "Windows Service", tactic: "Persistence" },
];

const SC_MANAGER_CONNECT:          u32 = 0x0001;
const SERVICE_CHANGE_CONFIG:       u32 = 0x0002;
const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;
const SC_ACTION_RESTART:           u32 = 1;
const DEFAULT_DELAY_MS:            u32 = 60000;

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
    change_service_config2_a(svc: usize, level: u32, info: *mut u8) -> i32,
    module = "advapi32.dll",
    api    = "ChangeServiceConfig2A"
);
dfr_fn!(
    close_service_handle(h: usize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

fn parse_u32(s: &str) -> Option<u32> {
    let mut v: u32 = 0;
    let mut any = false;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        any = true;
    }
    if any { Some(v) } else { None }
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
    let svc_name  = String::from(parser.get_str());
    let delay_str = String::from(parser.get_str());
    let svc_name  = svc_name.as_str();
    let delay_str = delay_str.as_str();

    if svc_name.is_empty() {
        return Err("usage: sc-failure <svc> [delay_ms]");
    }

    let delay_ms = if delay_str.is_empty() {
        DEFAULT_DELAY_MS
    } else {
        parse_u32(delay_str).ok_or("invalid delay")?
    };

    let mut svc_buf = [0u8; 256];
    if svc_name.len() >= svc_buf.len() - 1 { return Err("svc name too long"); }
    svc_buf[..svc_name.len()].copy_from_slice(svc_name.as_bytes());

    let scm = unsafe { open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT) }
        .map_err(|_| "open scm resolve")?;
    if scm == 0 { return Err("open scm failed"); }

    let h_svc = unsafe { open_service_a(scm, svc_buf.as_ptr() as *const i8, SERVICE_CHANGE_CONFIG) }
        .map_err(|_| "open svc resolve")?;
    if h_svc == 0 {
        unsafe { let _ = close_service_handle(scm); };
        return Err("open service failed");
    }

    // SC_ACTION: Type(u32), Delay(u32) — 8 bytes
    let mut sc_action = [0u8; 8];
    sc_action[0..4].copy_from_slice(&SC_ACTION_RESTART.to_le_bytes());
    sc_action[4..8].copy_from_slice(&delay_ms.to_le_bytes());

    let action_ptr = sc_action.as_ptr() as usize;

    // SERVICE_FAILURE_ACTIONS layout (40 bytes on x64):
    // dwResetPeriod(u32@0), [pad4@4], lpRebootMsg(*@8=NULL), lpCommand(*@16=NULL),
    // cActions(u32@24), [pad4@28], lpsaActions(*@32)
    let mut sfa = [0u8; 40];
    // dwResetPeriod = 0 (reset count on success after 0 seconds — use delay_ms)
    sfa[0..4].copy_from_slice(&0u32.to_le_bytes());
    // lpRebootMsg = NULL (bytes 8..16 already 0)
    // lpCommand = NULL (bytes 16..24 already 0)
    // cActions = 1
    sfa[24..28].copy_from_slice(&1u32.to_le_bytes());
    // lpsaActions pointer at offset 32
    let ptr_bytes = action_ptr.to_le_bytes();
    sfa[32..32 + ptr_bytes.len()].copy_from_slice(&ptr_bytes);

    let rc = unsafe {
        change_service_config2_a(h_svc, SERVICE_CONFIG_FAILURE_ACTIONS, sfa.as_mut_ptr())
    }.map_err(|_| "config2 resolve")?;

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(scm);
    };

    if rc == 0 { return Err("failure actions update failed"); }
    obf! { let ok = "failure actions set"; }
    println!("[+] {} ({}, delay={}ms)", ok, svc_name, delay_ms);
    Ok(())
}
