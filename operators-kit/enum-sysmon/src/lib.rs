// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Sysmon detection via three independent vectors:
//!   1. SCM service probe (Sysmon64 / Sysmon / SysmonDrv)
//!   2. Registry key probe for SysmonDrv\Parameters\HashingAlgorithm
//! All sensitive literals decrypted on-stack via obf!(). No child processes.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
];

// SCM constants
const SC_MANAGER_CONNECT:   u32 = 0x0001;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_RUNNING:      u32 = 0x0004;

// Registry constants
const HKLM: usize         = 0x80000002usize;
const KEY_QUERY_VALUE: u32 = 0x0001;
const ERROR_SUCCESS:   u32 = 0;

dfr_fn!(
    open_sc_manager_w(machine: *const u16, db: *const u16, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenSCManagerW"
);

dfr_fn!(
    open_service_w(scm: usize, name: *const u16, access: u32) -> usize,
    module = "advapi32.dll",
    api    = "OpenServiceW"
);

dfr_fn!(
    query_service_status(svc: usize, status: *mut ServiceStatus) -> i32,
    module = "advapi32.dll",
    api    = "QueryServiceStatus"
);

dfr_fn!(
    close_service_handle(h: usize) -> i32,
    module = "advapi32.dll",
    api    = "CloseServiceHandle"
);

dfr_fn!(
    reg_open_key_ex_w(
        hkey: usize, subkey: *const u16, options: u32,
        sam: u32, result: *mut usize,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExW"
);

dfr_fn!(
    reg_query_value_ex_w(
        hkey: usize, value: *const u16, reserved: *mut u32,
        reg_type: *mut u32, data: *mut u8, cb_data: *mut u32,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegQueryValueExW"
);

dfr_fn!(
    reg_close_key(hkey: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

#[repr(C)]
struct ServiceStatus {
    service_type:          u32,
    current_state:         u32,
    controls_accepted:     u32,
    win32_exit_code:       u32,
    service_specific_exit: u32,
    check_point:           u32,
    wait_hint:             u32,
}
impl ServiceStatus {
    fn new() -> Self {
        Self { service_type: 0, current_state: 0, controls_accepted: 0,
               win32_exit_code: 0, service_specific_exit: 0,
               check_point: 0, wait_hint: 0 }
    }
}

fn to_wide_64(s: &[u8]) -> ([u16; 64], usize) {
    let mut buf = [0u16; 64];
    let n = s.len().min(63);
    for (i, &b) in s[..n].iter().enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    (buf, n + 1)
}

fn to_wide_256(s: &[u8]) -> [u16; 256] {
    let mut buf = [0u16; 256];
    let n = s.len().min(255);
    for (i, &b) in s[..n].iter().enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    buf
}

fn probe_svc(scm: usize, name: &str) -> bool {
    let (wide, _) = to_wide_64(name.as_bytes());
    let h = match unsafe { open_service_w(scm, wide.as_ptr(), SERVICE_QUERY_STATUS) } {
        Ok(h) if h != 0 => h,
        _ => return false,
    };
    let mut status = ServiceStatus::new();
    let ok = unsafe { query_service_status(h, &mut status as *mut ServiceStatus) }
        .unwrap_or(0);
    unsafe { let _ = close_service_handle(h); };
    if ok != 0 {
        let state = if status.current_state == SERVICE_RUNNING { "RUNNING" } else { "STOPPED/PENDING" };
        println!("[+] Sysmon service detected: {} ({})", name, state);
        return true;
    }
    false
}

fn probe_registry() -> bool {
    // HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters
    obf! { let key_str = "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters"; }
    obf! { let val_str = "HashingAlgorithm"; }
    let key_wide = to_wide_256(key_str.as_bytes());
    let val_wide = to_wide_64(val_str.as_bytes());

    let mut hkey: usize = 0;
    let rc = unsafe {
        reg_open_key_ex_w(HKLM, key_wide.as_ptr(), 0, KEY_QUERY_VALUE, &mut hkey)
    }.unwrap_or(u32::MAX);
    if rc != ERROR_SUCCESS {
        return false;
    }
    let mut data = [0u8; 64];
    let mut cb: u32 = data.len() as u32;
    let mut reg_type: u32 = 0;
    let rc2 = unsafe {
        reg_query_value_ex_w(
            hkey, val_wide.0.as_ptr(), core::ptr::null_mut(),
            &mut reg_type, data.as_mut_ptr(), &mut cb,
        )
    }.unwrap_or(u32::MAX);
    unsafe { let _ = reg_close_key(hkey); };
    if rc2 == ERROR_SUCCESS {
        // HashingAlgorithm is REG_DWORD (4) — value is a bitmask of hash algorithms
        let algo = if cb >= 4 {
            u32::from_le_bytes([data[0], data[1], data[2], data[3]])
        } else { 0 };
        println!("[+] Sysmon registry key found — HashingAlgorithm=0x{:08x}", algo);
        return true;
    }
    false
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
    let mut detected = false;

    // --- Vector 1: SCM service probe ---
    let scm = unsafe {
        open_sc_manager_w(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT)
    }.map_err(|_| "scm resolve failed")?;
    if scm == 0 {
        return Err("scm open failed");
    }

    obf! { let svc64  = "Sysmon64";  }
    obf! { let svc32  = "Sysmon";    }
    obf! { let svcdrv = "SysmonDrv"; }

    if probe_svc(scm, svc64)  { detected = true; }
    if probe_svc(scm, svc32)  { detected = true; }
    if probe_svc(scm, svcdrv) { detected = true; }

    unsafe { let _ = close_service_handle(scm); };

    // --- Vector 2: Registry probe ---
    if probe_registry() { detected = true; }

    if detected {
        println!("[!] Sysmon IS present on this host — consider alternative evasion.");
    } else {
        println!("[-] Sysmon not detected (service + registry clean).");
    }
    Ok(())
}
