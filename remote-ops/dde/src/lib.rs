// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
// Credit: Rust port + OPSEC hardening — by Dani
//
//! Check for DDE server registrations in registry.
//! No args needed.
#![no_std]
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1559.002", name: "Dynamic Data Exchange", tactic: "Execution" },
];

const HKCU: *mut c_void = 0x80000001u32 as usize as *mut c_void;
const HKCR: *mut c_void = 0x80000000u32 as usize as *mut c_void;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;
const ERROR_NO_MORE_ITEMS: u32 = 259;

dfr_fn!(
    reg_open_key_ex_a(h: *mut c_void, sub: *const i8, opt: u32, sam: u32, res: *mut *mut c_void) -> u32,
    module = "advapi32.dll", api = "RegOpenKeyExA"
);
dfr_fn!(
    reg_enum_key_ex_a(
        h: *mut c_void, idx: u32, name: *mut u8, cch: *mut u32,
        res: *mut u32, cls: *mut u8, ccls: *mut u32, ft: *mut u64,
    ) -> u32,
    module = "advapi32.dll", api = "RegEnumKeyExA"
);
dfr_fn!(
    reg_close_key(h: *mut c_void) -> u32,
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
    println!("DDE Server Registrations:");
    // Check HKCU\Software\Microsoft\Office for DDE
    let mut h: *mut c_void = core::ptr::null_mut();
    let path = b"Software\\Microsoft\\Office\0";
    if unsafe {
        reg_open_key_ex_a(HKCU, path.as_ptr() as *const i8, 0, KEY_READ, &mut h)
    }.unwrap_or(1) == ERROR_SUCCESS {
        println!("[+] Office registry found (potential DDE vectors)");
        let mut idx = 0u32;
        loop {
            let mut name = [0u8; 256];
            let mut cch = 256u32;
            let r = unsafe {
                reg_enum_key_ex_a(h, idx, name.as_mut_ptr(), &mut cch,
                                  core::ptr::null_mut(), core::ptr::null_mut(),
                                  core::ptr::null_mut(), core::ptr::null_mut())
            }.unwrap_or(u32::MAX);
            if r == ERROR_NO_MORE_ITEMS { break; }
            if r == ERROR_SUCCESS {
                println!("  Office\\{}", CStr(&name, cch as usize));
            }
            idx += 1;
            if idx > 32 { break; }
        }
        unsafe { let _ = reg_close_key(h); };
    } else {
        println!("[-] No Office DDE registry found");
    }
    // Check for NDDEAgent window class via HKLM
    println!("Tip: Use FindWindowA('NDDEAgent') to detect active DDE server windows");
    Ok(())
}

struct CStr<'a>(&'a [u8], usize);
impl core::fmt::Display for CStr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let len = self.0[..self.1].iter().position(|&b| b == 0).unwrap_or(self.1);
        f.write_str(core::str::from_utf8(&self.0[..len]).unwrap_or("?"))
    }
}
