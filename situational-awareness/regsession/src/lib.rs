// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1012", name: "Query Registry", tactic: "Discovery" },
];

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

const HKEY_USERS: isize = 0x80000003u32 as i32 as isize;
const ERROR_NO_MORE_ITEMS: i32 = 259;

struct CStr { buf: [u8; 512], len: usize }
impl CStr {
    fn new() -> Self { Self { buf: [0u8; 512], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() { self.buf[self.len] = b; self.len += 1; }
    }
    fn as_str_safe(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}
impl core::fmt::Display for CStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"))
    }
}

fn cstr_from_ibuf(buf: &[i8], len: usize) -> CStr {
    let mut s = CStr::new();
    let cap = len.min(buf.len());
    for i in 0..cap {
        let b = buf[i] as u8;
        if b == 0 { break; }
        s.push(b);
    }
    s
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
    println!("Logged-on user sessions (HKU subkeys):");
    let mut idx: u32 = 0;
    let mut found = false;
    loop {
        let mut name_buf = [0i8; 256];
        let mut name_len: u32 = 256;
        let r = unsafe {
            reg_enum_key_ex_a(
                HKEY_USERS, idx,
                name_buf.as_mut_ptr(), &mut name_len,
                core::ptr::null_mut(), core::ptr::null_mut(),
                core::ptr::null_mut(), core::ptr::null_mut(),
            )
        }.unwrap_or(ERROR_NO_MORE_ITEMS);
        if r == ERROR_NO_MORE_ITEMS { break; }
        if r == 0 && name_len > 0 {
            let name = cstr_from_ibuf(&name_buf, name_len as usize);
            let s = name.as_str_safe();
            if !s.starts_with(".DEFAULT") && !s.ends_with("_Classes") {
                println!("  {}", name);
                found = true;
            }
        }
        idx += 1;
    }
    if !found {
        println!("[*] No user sessions found.");
    }
    Ok(())
}
