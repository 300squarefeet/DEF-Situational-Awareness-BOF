// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! QueryServiceConfigA — binPath, startType, service account.
//! Args: <servicename>
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::string::String;
use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1007", name: "System Service Discovery", tactic: "Discovery" },
];

const SC_MANAGER_CONNECT: u32  = 0x0001;
const SERVICE_QUERY_CONFIG: u32 = 0x0001;

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
    open_service_a(
        h_sc_manager: *mut core::ffi::c_void,
        lp_service_name: *const i8,
        dw_desired_access: u32,
    ) -> *mut core::ffi::c_void,
    module = "advapi32.dll",
    api    = "OpenServiceA"
);

dfr_fn!(
    query_service_config_a(
        h_service: *mut core::ffi::c_void,
        lp_service_config: *mut u8,
        cb_buf_size: u32,
        pcb_bytes_needed: *mut u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "QueryServiceConfigA"
);

dfr_fn!(
    close_service_handle(h_sc_object: *mut core::ffi::c_void) -> i32,
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
    let svc_s = String::from(parser.get_str());
    if svc_s.is_empty() {
        return Err("usage: sc-qc <servicename>");
    }

    let mut svc_buf = [0u8; 256];
    let slen = svc_s.len().min(255);
    svc_buf[..slen].copy_from_slice(&svc_s.as_bytes()[..slen]);

    let h_scm = unsafe {
        open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT)
    }.map_err(|_| "open failed")?;

    if h_scm.is_null() {
        return Err("open failed");
    }

    let h_svc = unsafe {
        open_service_a(h_scm, svc_buf.as_ptr() as *const i8, SERVICE_QUERY_CONFIG)
    }.map_err(|_| "open failed")?;

    if h_svc.is_null() {
        unsafe { let _ = close_service_handle(h_scm); };
        return Err("open failed");
    }

    // Two-pass QueryServiceConfigA
    let mut bytes_needed: u32 = 0;
    let _ = unsafe {
        query_service_config_a(h_svc, core::ptr::null_mut(), 0, &mut bytes_needed)
    };

    let cfg_bytes = if bytes_needed == 0 { 512 } else { bytes_needed };
    let mut cfg_buf: Vec<u8> = alloc::vec![0u8; cfg_bytes as usize];
    let ok = unsafe {
        query_service_config_a(
            h_svc,
            cfg_buf.as_mut_ptr(),
            cfg_buf.len() as u32,
            &mut bytes_needed,
        )
    }.unwrap_or(0);

    unsafe {
        let _ = close_service_handle(h_svc);
        let _ = close_service_handle(h_scm);
    };

    if ok == 0 {
        return Err("query failed");
    }

    // QUERY_SERVICE_CONFIGA layout (x64):
    // u32 dwServiceType    @ offset 0
    // u32 dwStartType      @ offset 4
    // u32 dwErrorControl   @ offset 8
    // pad 4 bytes          @ offset 12
    // *i8 lpBinaryPathName @ offset 16
    // *i8 lpLoadOrderGroup @ offset 24
    // *u32 lpdwTagId       @ offset 32
    // *i8 lpDependencies   @ offset 40
    // *i8 lpServiceStartName @ offset 48
    // *i8 lpDisplayName    @ offset 56
    let svc_type  = unsafe { core::ptr::read_unaligned(cfg_buf.as_ptr() as *const u32) };
    let start_u   = unsafe { core::ptr::read_unaligned(cfg_buf.as_ptr().add(4) as *const u32) };
    let err_ctrl  = unsafe { core::ptr::read_unaligned(cfg_buf.as_ptr().add(8) as *const u32) };
    let bin_ptr   = unsafe { core::ptr::read_unaligned(cfg_buf.as_ptr().add(16) as *const *const i8) };
    let acct_ptr  = unsafe { core::ptr::read_unaligned(cfg_buf.as_ptr().add(48) as *const *const i8) };
    let disp_ptr  = unsafe { core::ptr::read_unaligned(cfg_buf.as_ptr().add(56) as *const *const i8) };

    println!("Service  : {}", svc_s.as_str());
    println!("Type     : {}", svc_type_str(svc_type));
    println!("StartType: {}", svc_start(start_u));
    println!("ErrCtrl  : {}", err_ctrl);

    if !bin_ptr.is_null() {
        let bin = ptr_to_cstr(bin_ptr as *const u8, 512);
        println!("BinPath  : {}", bin);
    }
    if !acct_ptr.is_null() {
        let acct = ptr_to_cstr(acct_ptr as *const u8, 256);
        println!("Account  : {}", acct);
    }
    if !disp_ptr.is_null() {
        let disp = ptr_to_cstr(disp_ptr as *const u8, 256);
        println!("Display  : {}", disp);
    }

    Ok(())
}

fn svc_type_str(t: u32) -> &'static str {
    match t {
        0x01 => "KERNEL_DRIVER", 0x02 => "FILE_SYSTEM_DRIVER",
        0x10 => "WIN32_OWN_PROCESS", 0x20 => "WIN32_SHARE_PROCESS",
        0x110 => "WIN32_OWN_INTERACTIVE", 0x120 => "WIN32_SHARE_INTERACTIVE",
        _ => "UNKNOWN",
    }
}

fn svc_start(s: u32) -> &'static str {
    match s {
        0 => "BOOT", 1 => "SYSTEM", 2 => "AUTO", 3 => "DEMAND",
        4 => "DISABLED", _ => "UNKNOWN",
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
