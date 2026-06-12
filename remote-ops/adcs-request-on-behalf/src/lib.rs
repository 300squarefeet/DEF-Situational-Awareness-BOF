// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Check ADCS enrollment agent (ESC3) rights and autoenrollment config.
//! No args needed.
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1649", name: "Steal or Forge Authentication Certificates", tactic: "Credential Access" },
];

const HKLM: *mut c_void = 0x80000002u32 as usize as *mut c_void;
const HKCU: *mut c_void = 0x80000001u32 as usize as *mut c_void;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;
const ERROR_NO_MORE_ITEMS: u32 = 259;

dfr_fn!(
    reg_open_key_ex_a(
        h_key: *mut c_void, lp_sub_key: *const i8,
        ul_options: u32, sam_desired: u32, phk_result: *mut *mut c_void,
    ) -> u32,
    module = "advapi32.dll", api = "RegOpenKeyExA"
);
dfr_fn!(
    reg_enum_key_ex_a(
        h_key: *mut c_void, dw_index: u32, lp_name: *mut u8,
        lp_cch_name: *mut u32, lp_reserved: *mut u32,
        lp_class: *mut u8, lp_cch_class: *mut u32, lp_ft_last_write: *mut u64,
    ) -> u32,
    module = "advapi32.dll", api = "RegEnumKeyExA"
);
dfr_fn!(
    reg_query_value_ex_a(
        h_key: *mut c_void, lp_value_name: *const i8, lp_reserved: *mut u32,
        lp_type: *mut u32, lp_data: *mut u8, lp_cb_data: *mut u32,
    ) -> u32,
    module = "advapi32.dll", api = "RegQueryValueExA"
);
dfr_fn!(
    reg_enum_value_a(
        h_key: *mut c_void, dw_index: u32,
        lp_value_name: *mut u8, lp_cch_value_name: *mut u32,
        lp_reserved: *mut u32, lp_type: *mut u32,
        lp_data: *mut u8, lp_cb_data: *mut u32,
    ) -> u32,
    module = "advapi32.dll", api = "RegEnumValueA"
);
dfr_fn!(
    reg_close_key(h_key: *mut c_void) -> u32,
    module = "advapi32.dll", api = "RegCloseKey"
);

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    println!("Checking ADCS enrollment agent (ESC3) configuration:");

    // Check HKCU autoenrollment
    let autoenroll = b"SOFTWARE\\Microsoft\\Cryptography\\Autoenrollment\0";
    let mut h: *mut c_void = core::ptr::null_mut();
    if unsafe {
        reg_open_key_ex_a(HKCU, autoenroll.as_ptr() as *const i8, 0, KEY_READ, &mut h)
    }.unwrap_or(1) == ERROR_SUCCESS {
        println!("[+] HKCU Autoenrollment key exists");
        let mut idx = 0u32;
        loop {
            let mut name = [0u8; 256];
            let mut nlen = 256u32;
            let mut data = [0u8; 256];
            let mut dlen = 256u32;
            let mut typ = 0u32;
            let r = unsafe {
                reg_enum_value_a(h, idx, name.as_mut_ptr(), &mut nlen,
                                 core::ptr::null_mut(), &mut typ,
                                 data.as_mut_ptr(), &mut dlen)
            }.unwrap_or(u32::MAX);
            if r == ERROR_NO_MORE_ITEMS { break; }
            if r == ERROR_SUCCESS {
                let nl = nlen as usize;
                let dl = (dlen as usize).min(255);
                println!("    {}: {}", CStr(&name, nl), CStr(&data, dl));
            }
            idx += 1;
        }
        unsafe { let _ = reg_close_key(h); };
    } else {
        println!("[-] No HKCU autoenrollment configuration");
    }

    // Check HKLM CertSvc CA policy modules
    let policy = b"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\0";
    let mut h_cs: *mut c_void = core::ptr::null_mut();
    if unsafe {
        reg_open_key_ex_a(HKLM, policy.as_ptr() as *const i8, 0, KEY_READ, &mut h_cs)
    }.unwrap_or(1) == ERROR_SUCCESS {
        println!("[+] Local ADCS CA detected");
        let mut idx = 0u32;
        loop {
            let mut ca_name = [0u8; 256];
            let mut cch = 256u32;
            let r = unsafe {
                reg_enum_key_ex_a(h_cs, idx, ca_name.as_mut_ptr(), &mut cch,
                                  core::ptr::null_mut(), core::ptr::null_mut(),
                                  core::ptr::null_mut(), core::ptr::null_mut())
            }.unwrap_or(u32::MAX);
            if r == ERROR_NO_MORE_ITEMS { break; }
            if r == ERROR_SUCCESS {
                println!("  CA: {}", CStr(&ca_name, cch as usize));
            }
            idx += 1;
        }
        unsafe { let _ = reg_close_key(h_cs); };
    } else {
        println!("[-] No local ADCS CA (CertSvc) found");
    }

    println!("Note: ESC3 requires enrollment agent template with EKU=1.3.6.1.4.1.311.20.2.1");
    Ok(())
}

struct CStr<'a>(&'a [u8], usize);
impl core::fmt::Display for CStr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let len = self.0[..self.1].iter().position(|&b| b == 0).unwrap_or(self.1);
        f.write_str(core::str::from_utf8(&self.0[..len]).unwrap_or("?"))
    }
}
