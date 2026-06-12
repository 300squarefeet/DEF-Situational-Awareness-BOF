// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Enumerate ADCS Certificate Authority configuration from registry.
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
    let certsvc_path = b"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\0";
    let mut h_certsvc: *mut c_void = core::ptr::null_mut();

    let rc = unsafe {
        reg_open_key_ex_a(HKLM, certsvc_path.as_ptr() as *const i8,
                          0, KEY_READ, &mut h_certsvc)
    }.map_err(|_| "reg query failed")?;

    if rc != ERROR_SUCCESS {
        println!("ADCS not installed on this host (CertSvc not found)");
        return Ok(());
    }

    println!("ADCS Certificate Authorities:");
    let mut idx = 0u32;
    loop {
        let mut name = [0u8; 256];
        let mut cch = 256u32;
        let r = unsafe {
            reg_enum_key_ex_a(h_certsvc, idx, name.as_mut_ptr(), &mut cch,
                              core::ptr::null_mut(), core::ptr::null_mut(),
                              core::ptr::null_mut(), core::ptr::null_mut())
        }.unwrap_or(u32::MAX);
        if r == ERROR_NO_MORE_ITEMS { break; }
        if r != ERROR_SUCCESS { idx += 1; continue; }

        let nlen = cch as usize;
        println!("  CA: {}", CStr::from_bytes(&name, nlen));

        // Open CA subkey and read config values
        let mut h_ca: *mut c_void = core::ptr::null_mut();
        if unsafe {
            reg_open_key_ex_a(h_certsvc, name.as_ptr() as *const i8,
                              0, KEY_READ, &mut h_ca)
        }.unwrap_or(1) == ERROR_SUCCESS {
            query_and_print(h_ca, b"CACertPublicationURLs\0", "  PublicationURLs");
            query_and_print(h_ca, b"CRLPublicationURLs\0", "  CRLURLs");
            query_and_print(h_ca, b"CertEnrollCompatFlags\0", "  EnrollFlags");
            unsafe { let _ = reg_close_key(h_ca); };
        }
        idx += 1;
    }

    unsafe { let _ = reg_close_key(h_certsvc); };
    Ok(())
}

fn query_and_print(h_key: *mut c_void, value: &[u8], label: &str) {
    let mut data = [0u8; 512];
    let mut cb = 512u32;
    let mut typ = 0u32;
    let r = unsafe {
        reg_query_value_ex_a(h_key, value.as_ptr() as *const i8,
                             core::ptr::null_mut(), &mut typ,
                             data.as_mut_ptr(), &mut cb)
    }.unwrap_or(1);
    if r == ERROR_SUCCESS && cb > 0 {
        let len = (cb as usize).min(511);
        rustbof::println!("{}: {}", label, CStr::from_bytes(&data, len));
    }
}

fn cstr_len(buf: &[u8], max: usize) -> usize {
    let mut i = 0; while i < max && buf[i] != 0 { i += 1; } i
}

struct CStr<'a>(&'a [u8]);
impl<'a> CStr<'a> {
    fn from_bytes(buf: &'a [u8], len: usize) -> Self {
        let real = buf[..len].iter().position(|&b| b == 0).unwrap_or(len);
        Self(&buf[..real])
    }
}
impl core::fmt::Display for CStr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(self.0).unwrap_or("?"))
    }
}
