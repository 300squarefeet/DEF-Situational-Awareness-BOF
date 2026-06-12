// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Set service description via ChangeServiceConfig2A.
//! Args: <servicename> <description>
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1543.003", name: "Windows Service", tactic: "Persistence" },
];

const SC_MANAGER_CONNECT:     u32 = 0x0001;
const SERVICE_CHANGE_CONFIG:  u32 = 0x0002;
const SERVICE_CONFIG_DESCRIPTION: u32 = 1;

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
    let desc_str = String::from(parser.get_str());
    let svc_name = svc_name.as_str();
    let desc_str = desc_str.as_str();

    if svc_name.is_empty() || desc_str.is_empty() {
        return Err("usage: sc-description <svc> <description>");
    }

    let mut svc_buf  = [0u8; 256];
    let mut desc_buf = [0u8; 1024];
    if svc_name.len() >= svc_buf.len() - 1 { return Err("svc name too long"); }
    if desc_str.len() >= desc_buf.len() - 1 { return Err("description too long"); }
    svc_buf[..svc_name.len()].copy_from_slice(svc_name.as_bytes());
    desc_buf[..desc_str.len()].copy_from_slice(desc_str.as_bytes());

    let scm = unsafe { open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT) }
        .map_err(|_| "open scm resolve")?;
    if scm == 0 { return Err("open scm failed"); }

    let h_svc = unsafe { open_service_a(scm, svc_buf.as_ptr() as *const i8, SERVICE_CHANGE_CONFIG) }
        .map_err(|_| "open svc resolve")?;
    if h_svc == 0 {
        unsafe { let _ = close_service_handle(scm); };
        return Err("open service failed");
    }

    // SERVICE_DESCRIPTION layout: just a pointer to the description string at offset 0.
    // We embed the pointer value as bytes in an 8-byte struct.
    let desc_ptr = desc_buf.as_ptr() as usize;
    let mut svc_desc_buf = [0u8; 8];
    let ptr_bytes = desc_ptr.to_le_bytes();
    svc_desc_buf[..ptr_bytes.len()].copy_from_slice(&ptr_bytes);

    let rc = unsafe {
        change_service_config2_a(h_svc, SERVICE_CONFIG_DESCRIPTION, svc_desc_buf.as_mut_ptr())
    }.map_err(|_| "config2 resolve")?;

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(scm);
    };

    if rc == 0 { return Err("description update failed"); }
    obf! { let ok = "description updated"; }
    println!("[+] {} ({})", ok, svc_name);
    Ok(())
}
