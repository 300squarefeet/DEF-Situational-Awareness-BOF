// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
#![no_std]
#![cfg_attr(not(test), no_main)]


use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" },
];

const HKEY_LOCAL_MACHINE: usize = 0x80000002usize;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;
const ERROR_NO_MORE_ITEMS: u32 = 259;

dfr_fn!(
    reg_open_key_ex_a(
        hkey: usize, subkey: *const i8, options: u32,
        sam_desired: u32, result: *mut usize,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_enum_key_ex_a(
        hkey: usize, index: u32,
        name: *mut i8, name_len: *mut u32,
        reserved: *mut u32,
        class_buf: *mut i8, class_len: *mut u32,
        last_write: *mut u64,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegEnumKeyExA"
);

dfr_fn!(
    reg_query_value_ex_a(
        hkey: usize, value: *const i8, reserved: *mut u32,
        reg_type: *mut u32, data: *mut u8, data_len: *mut u32,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegQueryValueExA"
);

dfr_fn!(
    reg_close_key(hkey: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

// Firewall rules registry path — obfuscated at compile time, decrypted on-stack
#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    obf_cstr! {
        let fw_key = c"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
    }

    let mut hkey: usize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(HKEY_LOCAL_MACHINE, fw_key.as_ptr() as *const i8, 0, KEY_READ, &mut hkey)
    }.map_err(|_| "resolve failed")?;

    if rc != ERROR_SUCCESS {
        return Err("FirewallRules key open failed");
    }

    println!("FIREWALL RULES:");
    println!("{}", "--------------------------------------------");

    let mut name_buf = [0i8; 512];
    let mut val_buf: Vec<u8> = alloc::vec![0u8; 2048];
    let mut idx: u32 = 0;

    loop {
        let mut name_len: u32 = 511;
        // Clear name buffer
        for b in name_buf.iter_mut() { *b = 0; }

        // Enumerate value names directly (firewall rules are values, not subkeys)
        let mut reg_type: u32 = 0;
        let mut val_len: u32 = 2047;
        for b in val_buf.iter_mut() { *b = 0; }

        let rc2 = unsafe {
            reg_enum_key_ex_a(
                hkey, idx,
                name_buf.as_mut_ptr(), &mut name_len,
                core::ptr::null_mut(),
                core::ptr::null_mut(), core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }.map_err(|_| "resolve failed")?;

        if rc2 == ERROR_NO_MORE_ITEMS { break; }
        if rc2 != ERROR_SUCCESS { idx += 1; continue; }

        let name_s = cstr_to_str(name_buf.as_ptr() as *const u8, name_len as usize);
        println!("[Rule] {}", name_s);
        idx += 1;
    }

    unsafe { let _ = reg_close_key(hkey); };
    Ok(())
}

fn cstr_to_str(ptr: *const u8, max: usize) -> ByteStr {
    let mut s = ByteStr::new();
    if ptr.is_null() { return s; }
    for i in 0..max {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 { break; }
        s.push(b);
    }
    s
}

struct ByteStr { buf: [u8; 256], len: usize }
impl ByteStr {
    fn new() -> Self { Self { buf: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Display for ByteStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
