// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
#![no_std]
#![cfg_attr(not(test), no_main)]


use alloc::vec::Vec;

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf, obf_cstr};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1012", name: "Query Registry", tactic: "Discovery" },
];

const HKEY_LOCAL_MACHINE: usize = 0x80000002usize;
const HKEY_CURRENT_USER: usize  = 0x80000001usize;
const KEY_QUERY_VALUE: u32  = 0x0001;
const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
const KEY_READ: u32 = 0x20019;
const REG_OPTION_NON_VOLATILE: u32 = 0;
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
    reg_query_info_key_a(
        hkey: usize,
        class: *mut i8, class_len: *mut u32,
        reserved: *mut u32,
        num_subkeys: *mut u32, max_subkey_len: *mut u32,
        max_class_len: *mut u32,
        num_values: *mut u32, max_value_name_len: *mut u32,
        max_value_len: *mut u32,
        security_descriptor: *mut u32, last_write: *mut u64,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegQueryInfoKeyA"
);

dfr_fn!(
    reg_enum_value_a(
        hkey: usize,
        index: u32,
        value_name: *mut i8, value_name_len: *mut u32,
        reserved: *mut u32,
        reg_type: *mut u32,
        data: *mut u8, data_len: *mut u32,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegEnumValueA"
);

dfr_fn!(
    reg_close_key(hkey: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
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
    // Default: query the run key (common recon target). Path is obfuscated
    // at compile time and decrypted on-stack to avoid plaintext in .rdata.
    obf_cstr! {
        let key_path = c"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    }
    let hroot = HKEY_LOCAL_MACHINE;

    let mut hkey: usize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(hroot, key_path.as_ptr() as *const i8, 0, KEY_READ, &mut hkey)
    }.map_err(|_| "resolve failed")?;

    if rc != ERROR_SUCCESS {
        return Err("key open failed");
    }

    let mut num_values: u32 = 0;
    let mut max_name_len: u32 = 0;
    let mut max_val_len: u32 = 0;

    let rc2 = unsafe {
        reg_query_info_key_a(
            hkey,
            core::ptr::null_mut(), core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(), core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut num_values, &mut max_name_len,
            &mut max_val_len,
            core::ptr::null_mut(), core::ptr::null_mut(),
        )
    }.map_err(|_| "resolve failed")?;

    if rc2 != ERROR_SUCCESS {
        unsafe { let _ = reg_close_key(hkey); };
        return Err("key query failed");
    }

    obf! {
        let key_label = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    }
    println!("KEY: HKLM\\{}", key_label);
    println!("{} values:", num_values);
    println!("{:<40} {:<12} {}", "Name", "Type", "Data");
    println!("{}", "-----------------------------------------------------------");

    let name_buf_size = (max_name_len + 1) as usize;
    let val_buf_size  = (max_val_len + 1) as usize;
    let mut name_buf: Vec<u8> = alloc::vec![0u8; name_buf_size];
    let mut val_buf:  Vec<u8> = alloc::vec![0u8; val_buf_size];

    for idx in 0..num_values {
        let mut name_len: u32 = name_buf_size as u32;
        let mut val_len:  u32 = val_buf_size  as u32;
        let mut reg_type: u32 = 0;

        // Zero buffers
        for b in name_buf.iter_mut() { *b = 0; }
        for b in val_buf.iter_mut()  { *b = 0; }

        let rc3 = unsafe {
            reg_enum_value_a(
                hkey, idx,
                name_buf.as_mut_ptr() as *mut i8, &mut name_len,
                core::ptr::null_mut(),
                &mut reg_type,
                val_buf.as_mut_ptr(), &mut val_len,
            )
        }.map_err(|_| "resolve failed")?;

        if rc3 == ERROR_NO_MORE_ITEMS { break; }
        if rc3 != ERROR_SUCCESS { continue; }

        let name_s = core::str::from_utf8(&name_buf[..name_len as usize]).unwrap_or("?");
        let type_s = reg_type_str(reg_type);
        let data_s = fmt_reg_data(&val_buf[..val_len as usize], reg_type);
        println!("{:<40} {:<12} {}", name_s, type_s, data_s);
    }

    unsafe { let _ = reg_close_key(hkey); };
    Ok(())
}

fn reg_type_str(t: u32) -> &'static str {
    match t {
        1 => "REG_SZ", 2 => "REG_EXPAND_SZ", 3 => "REG_BINARY",
        4 => "REG_DWORD", 7 => "REG_MULTI_SZ", 11 => "REG_QWORD",
        _ => "UNKNOWN",
    }
}

fn fmt_reg_data(data: &[u8], reg_type: u32) -> DataStr {
    let mut s = DataStr::new();
    match reg_type {
        1 | 2 | 7 => {
            // String — UTF-8 or strip NULs
            for &b in data {
                if b == 0 { continue; }
                s.push(b);
            }
        }
        4 => {
            if data.len() >= 4 {
                let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                use core::fmt::Write;
                let _ = write!(s, "0x{:08x}", v);
            }
        }
        _ => {
            for &b in data.iter().take(16) {
                use core::fmt::Write;
                let _ = write!(s, "{:02x}", b);
            }
        }
    }
    s
}

struct DataStr { buf: [u8; 128], len: usize }
impl DataStr {
    fn new() -> Self { Self { buf: [0u8; 128], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
}
impl core::fmt::Write for DataStr {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() { self.push(b); }
        Ok(())
    }
}
impl core::fmt::Display for DataStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}
