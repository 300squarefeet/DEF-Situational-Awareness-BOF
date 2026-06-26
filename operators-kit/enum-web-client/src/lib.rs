// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1135", name: "Network Share Discovery", tactic: "Discovery" },
];

const SC_MANAGER_CONNECT:   u32   = 0x0001u32;
const SERVICE_QUERY_STATUS: u32   = 0x0004u32;
const SC_STATUS_PROCESS_INFO: u32 = 0u32;
const HKLM:                 usize = 0x80000002usize;
const KEY_READ:             u32   = 0x20019u32;

dfr_fn!(
    open_sc_manager_a(machine: *const i8, db: *const i8, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenSCManagerA"
);

dfr_fn!(
    open_service_a(scm: usize, svc_name: *const i8, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenServiceA"
);

dfr_fn!(
    query_service_status_ex(
        svc: usize,
        info_level: u32,
        buf: *mut u8,
        buf_size: u32,
        bytes_needed: *mut u32
    ) -> i32,
    module = "advapi32.dll",
    api    = "QueryServiceStatusEx"
);

dfr_fn!(
    close_service_handle(h: usize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

dfr_fn!(
    reg_open_key_ex_a(
        key: usize,
        subkey: *const i8,
        reserved: u32,
        access: u32,
        result: *mut usize
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_query_value_ex_a(
        key: usize,
        value: *const i8,
        reserved: *mut u32,
        vtype: *mut u32,
        data: *mut u8,
        data_size: *mut u32
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegQueryValueExA"
);

dfr_fn!(
    reg_close_key(key: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

fn state_str(state: u32) -> &'static str {
    match state {
        1 => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        4 => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => "UNKNOWN",
    }
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    println!("WEBCLIENT / WEBDAV CHECK:");
    println!("{}", "--------------------------------------------");

    // ---- 1. Service status check ----
    // "WebClient\0" as i8 array on stack
    let svc_name: [i8; 10] = [
        b'W' as i8, b'e' as i8, b'b' as i8, b'C' as i8, b'l' as i8,
        b'i' as i8, b'e' as i8, b'n' as i8, b't' as i8, 0i8,
    ];

    let scm = unsafe {
        open_sc_manager_a(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT)
    }.map_err(|_| "scm resolve")?;

    if scm == 0 {
        return Err("scm open");
    }

    let svc = unsafe {
        open_service_a(scm, svc_name.as_ptr(), SERVICE_QUERY_STATUS)
    }.unwrap_or(0);

    if svc != 0 {
        // SERVICE_STATUS_PROCESS = 36 bytes; current_state at offset 4 (u32)
        let mut status_buf = [0u8; 36];
        let mut bytes_needed: u32 = 0;
        let ok = unsafe {
            query_service_status_ex(
                svc,
                SC_STATUS_PROCESS_INFO,
                status_buf.as_mut_ptr(),
                36u32,
                &mut bytes_needed,
            )
        }.unwrap_or(0);

        if ok != 0 {
            let current_state = u32::from_le_bytes([
                status_buf[4], status_buf[5], status_buf[6], status_buf[7],
            ]);
            println!("  [Service] WebClient state: {}", state_str(current_state));
        } else {
            println!("  [Service] WebClient: query failed");
        }
        unsafe { let _ = close_service_handle(svc); };
    } else {
        println!("  [Service] WebClient: not found / no access");
    }

    unsafe { let _ = close_service_handle(scm); };

    // ---- 2. Registry proxy config check ----
    // Key: "SYSTEM\CurrentControlSet\Services\WebClient\Parameters\0"
    let reg_key: &[i8] = &[
        b'S' as i8, b'Y' as i8, b'S' as i8, b'T' as i8, b'E' as i8, b'M' as i8,
        b'\\' as i8,
        b'C' as i8, b'u' as i8, b'r' as i8, b'r' as i8, b'e' as i8, b'n' as i8,
        b't' as i8, b'C' as i8, b'o' as i8, b'n' as i8, b't' as i8, b'r' as i8,
        b'o' as i8, b'l' as i8, b'S' as i8, b'e' as i8, b't' as i8,
        b'\\' as i8,
        b'S' as i8, b'e' as i8, b'r' as i8, b'v' as i8, b'i' as i8, b'c' as i8,
        b'e' as i8, b's' as i8,
        b'\\' as i8,
        b'W' as i8, b'e' as i8, b'b' as i8, b'C' as i8, b'l' as i8, b'i' as i8,
        b'e' as i8, b'n' as i8, b't' as i8,
        b'\\' as i8,
        b'P' as i8, b'a' as i8, b'r' as i8, b'a' as i8, b'm' as i8, b'e' as i8,
        b't' as i8, b'e' as i8, b'r' as i8, b's' as i8,
        0i8,
    ];

    // Value name: "ProxyServer\0"
    let proxy_val: [i8; 12] = [
        b'P' as i8, b'r' as i8, b'o' as i8, b'x' as i8, b'y' as i8,
        b'S' as i8, b'e' as i8, b'r' as i8, b'v' as i8, b'e' as i8, b'r' as i8,
        0i8,
    ];

    let mut reg_handle: usize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(
            HKLM,
            reg_key.as_ptr(),
            0u32,
            KEY_READ,
            &mut reg_handle,
        )
    }.map_err(|_| "reg open resolve")?;

    if rc == 0 && reg_handle != 0 {
        let mut data_buf = [0u8; 256];
        let mut data_size: u32 = 256u32;
        let mut vtype: u32 = 0u32;
        let mut reserved: u32 = 0u32;

        let qrc = unsafe {
            reg_query_value_ex_a(
                reg_handle,
                proxy_val.as_ptr(),
                &mut reserved,
                &mut vtype,
                data_buf.as_mut_ptr(),
                &mut data_size,
            )
        }.unwrap_or(u32::MAX);

        if qrc == 0 && data_size > 0 {
            let len = (data_size as usize).min(255);
            // Find NUL terminator
            let end = data_buf[..len].iter().position(|&b| b == 0).unwrap_or(len);
            let proxy_str = core::str::from_utf8(&data_buf[..end]).unwrap_or("?");
            println!("  [Registry] ProxyServer: {}", proxy_str);
        } else {
            println!("  [Registry] ProxyServer: (not set)");
        }

        unsafe { let _ = reg_close_key(reg_handle); };
    } else {
        println!("  [Registry] WebClient\\Parameters: key not found");
    }

    Ok(())
}
