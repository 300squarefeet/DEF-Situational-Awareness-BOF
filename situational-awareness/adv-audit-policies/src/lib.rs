// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1201", name: "Password Policy Discovery", tactic: "Discovery" },
];

const HKLM: isize = 0x80000002u32 as i32 as isize;
const KEY_READ: u32 = 0x20019;
const ERROR_NO_MORE_ITEMS: i32 = 259;

dfr_fn!(
    reg_open_key_ex_a(
        hKey: isize,
        lpSubKey: *const i8,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut isize
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_enum_value_a(
        hKey: isize,
        dwIndex: u32,
        lpValueName: *mut i8,
        lpcchValueName: *mut u32,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32
    ) -> i32,
    module = "advapi32.dll",
    api    = "RegEnumValueA"
);

dfr_fn!(
    reg_close_key(hKey: isize) -> i32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

// ---- helpers ---------------------------------------------------------------

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

fn cstr_from_ibuf(buf: &[i8], len: usize) -> CStr {
    let mut s = CStr::new();
    let count = len.min(buf.len());
    for i in 0..count {
        s.push(buf[i] as u8);
    }
    s
}

// ---- entry -----------------------------------------------------------------

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    let path = b"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Audit\0";
    let mut hkey: isize = 0;
    let ret = unsafe {
        reg_open_key_ex_a(HKLM, path.as_ptr() as *const i8, 0, KEY_READ, &mut hkey)
    }.unwrap_or(-1);
    if ret != 0 || hkey == 0 {
        println!("[*] Audit policy key not found.");
        return Ok(());
    }

    println!("Advanced Audit Policies:");
    let mut idx: u32 = 0;
    loop {
        let mut name_buf = [0i8; 256];
        let mut name_len: u32 = 256;
        let mut val_type: u32 = 0;
        let mut data = [0u8; 4];
        let mut data_len: u32 = 4;
        let r = unsafe {
            reg_enum_value_a(
                hkey,
                idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                core::ptr::null_mut(),
                &mut val_type,
                data.as_mut_ptr(),
                &mut data_len,
            )
        }.unwrap_or(ERROR_NO_MORE_ITEMS);
        if r == ERROR_NO_MORE_ITEMS { break; }
        if r == 0 {
            let name = cstr_from_ibuf(&name_buf, name_len as usize);
            let val = u32::from_le_bytes(data);
            println!("  {}: {}", name, val);
        }
        idx += 1;
    }

    unsafe { let _ = reg_close_key(hkey); };
    Ok(())
}
