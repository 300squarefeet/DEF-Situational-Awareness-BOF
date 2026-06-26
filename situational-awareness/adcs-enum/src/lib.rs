// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening
//
//! Non-COM ADCS enumeration via registry walk.
//! Walks HKLM\SOFTWARE\Microsoft\Cryptography\Services\CertSvc\Configuration\<CA>
//! and prints CA name + DNS hostname.
//! Args: (none)
#![no_std]
#![cfg_attr(not(test), no_main)]

use alloc::vec::Vec;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Software Discovery: Security Software Discovery", tactic: "Discovery" },
];

const HKEY_LOCAL_MACHINE: isize = -2147483646i32 as isize;
const KEY_READ: u32             = 0x20019;
const ERROR_NO_MORE_ITEMS: i32  = 259;

dfr_fn!(
    reg_open_key_ex_a(
        h_key: isize,
        lp_sub_key: *const i8,
        ul_options: u32,
        sam_desired: u32,
        ph_key_result: *mut isize,
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_enum_key_ex_a(
        h_key: isize,
        dw_index: u32,
        lp_name: *mut i8,
        lp_cch_name: *mut u32,
        lp_reserved: *mut u32,
        lp_class: *mut i8,
        lp_cch_class: *mut u32,
        lp_ft_last_write_time: *mut u64,
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegEnumKeyExA"
);

dfr_fn!(
    reg_query_value_ex_a(
        h_key: isize,
        lp_value_name: *const i8,
        lp_reserved: *mut u32,
        lp_type: *mut u32,
        lp_data: *mut u8,
        lp_cb_data: *mut u32,
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegQueryValueExA"
);

dfr_fn!(
    reg_close_key(h_key: isize) -> i32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Registry path for CertSvc configuration
    let path_buf = b"SOFTWARE\\Microsoft\\Cryptography\\Services\\CertSvc\\Configuration\0";

    let mut h_config: isize = 0;
    let ret = unsafe {
        reg_open_key_ex_a(
            HKEY_LOCAL_MACHINE,
            path_buf.as_ptr() as *const i8,
            0,
            KEY_READ,
            &mut h_config,
        )
    }.unwrap_or(-1);

    if ret != 0 || h_config == 0 {
        println!("[*] No ADCS CertSvc configuration found (CertSvc not installed or insufficient rights).");
        return Ok(());
    }

    println!("ADCS Certificate Authorities:");
    println!("{:<40} {}", "CA Name", "DNS Hostname");
    println!("{}", "-".repeat(70));

    let mut found = false;
    let mut idx: u32 = 0;

    loop {
        let mut name_buf = [0i8; 256];
        let mut name_len: u32 = 256;

        let enum_ret = unsafe {
            reg_enum_key_ex_a(
                h_config,
                idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }.unwrap_or(ERROR_NO_MORE_ITEMS);

        if enum_ret == ERROR_NO_MORE_ITEMS {
            break;
        }
        if enum_ret != 0 {
            idx += 1;
            continue;
        }

        found = true;
        let ca_name = cstr_from_buf(&name_buf[..name_len as usize]);

        // Open the CA sub-key to read CAServerName (DNS hostname)
        let mut h_ca: isize = 0;
        let sub_ret = unsafe {
            reg_open_key_ex_a(
                h_config,
                name_buf.as_ptr(),
                0,
                KEY_READ,
                &mut h_ca,
            )
        }.unwrap_or(-1);

        let hostname = if sub_ret == 0 && h_ca != 0 {
            let dns_buf_key = b"CAServerName\0";

            let mut val_type: u32 = 0;
            let mut data_buf: Vec<u8> = alloc::vec![0u8; 512];
            let mut data_len: u32 = data_buf.len() as u32;

            let qret = unsafe {
                reg_query_value_ex_a(
                    h_ca,
                    dns_buf_key.as_ptr() as *const i8,
                    core::ptr::null_mut(),
                    &mut val_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                )
            }.unwrap_or(-1);

            unsafe { let _ = reg_close_key(h_ca); };

            if qret == 0 && data_len > 0 {
                let end = data_len as usize;
                let end = if end > 0 && data_buf[end - 1] == 0 { end - 1 } else { end };
                let s = ptr_to_cstr(data_buf.as_ptr(), end.min(511));
                s
            } else {
                ptr_to_cstr(b"(unknown)\0".as_ptr(), 9)
            }
        } else {
            ptr_to_cstr(b"(unknown)\0".as_ptr(), 9)
        };

        println!("{:<40} {}", ca_name, hostname);
        idx += 1;
    }

    unsafe { let _ = reg_close_key(h_config); };

    if !found {
        println!("(no CA subkeys found)");
    }

    Ok(())
}

fn cstr_from_buf(buf: &[i8]) -> CStr {
    let mut s = CStr::new();
    for &c in buf {
        if c == 0 { break; }
        s.push(c as u8);
    }
    s
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
