// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
// Project: DEF-Situational-Awareness-BOF — Dani RustBOF OPSEC Suite
//
//! Enumerate Windows Defender exclusions from the registry.
//! Reads Paths, Extensions, and Processes exclusion keys from HKLM.
//! No arguments required.
#![no_std]
#![cfg_attr(not(test), no_main)]

use rustbof::{println, eprintln};
use common::{mitre::Technique, dfr_fn, obf};

const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion" },
];

const HKLM:               usize = 0x80000002usize;
const KEY_READ:           u32   = 0x20019u32;
const ERROR_SUCCESS:      u32   = 0u32;
const ERROR_NO_MORE_ITEMS: u32  = 259u32;

dfr_fn!(
    reg_open_key_ex_a(
        key:      usize,
        subkey:   *const i8,
        reserved: u32,
        access:   u32,
        result:   *mut usize
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegOpenKeyExA"
);

dfr_fn!(
    reg_enum_value_a(
        key:       usize,
        index:     u32,
        name:      *mut u8,
        name_len:  *mut u32,
        reserved:  *mut u32,
        vtype:     *mut u32,
        data:      *mut u8,
        data_len:  *mut u32
    ) -> u32,
    module = "advapi32.dll",
    api    = "RegEnumValueA"
);

dfr_fn!(
    reg_close_key(key: usize) -> u32,
    module = "advapi32.dll",
    api    = "RegCloseKey"
);

/// Enumerate all values under `hkey` and print them with the given `label`.
fn enum_exclusion_key(hkey: usize, label: &str) {
    let mut index: u32 = 0;
    loop {
        let mut name_buf  = [0u8; 256];
        let mut name_len: u32 = 256;
        let mut data_buf  = [0u8; 1024];
        let mut data_len: u32 = 1024;
        let mut vtype:    u32 = 0;
        let mut reserved: u32 = 0;

        let rc = unsafe {
            reg_enum_value_a(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                &mut reserved,
                &mut vtype,
                data_buf.as_mut_ptr(),
                &mut data_len,
            )
        }.unwrap_or(u32::MAX);

        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS {
            break;
        }

        let name_end = (name_len as usize).min(255);
        if let Ok(name_str) = core::str::from_utf8(&name_buf[..name_end]) {
            println!("  [{}] {}", label, name_str);
        }

        index += 1;
    }
}

#[rustbof::main]
fn main() {
    common::mitre::print_banner(env!("CARGO_PKG_NAME"), TECHNIQUES);
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("[!] {}: {}", env!("CARGO_PKG_NAME"), e),
    }
}

fn run() -> Result<(), &'static str> {
    // Key paths as NUL-terminated byte arrays (obf! decrypts on-stack)
    obf! { let paths_key      = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\0"; }
    obf! { let ext_key        = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\0"; }
    obf! { let processes_key  = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\0"; }

    let exclusion_defs: [(&str, &str); 3] = [
        (paths_key,     "Paths"),
        (ext_key,       "Extensions"),
        (processes_key, "Processes"),
    ];

    let mut any_found = false;

    for (key_path, label) in &exclusion_defs {
        let mut hkey: usize = 0;
        let rc = unsafe {
            reg_open_key_ex_a(
                HKLM,
                key_path.as_ptr() as *const i8,
                0,
                KEY_READ,
                &mut hkey,
            )
        }.unwrap_or(u32::MAX);

        if rc == ERROR_SUCCESS && hkey != 0 {
            println!("[+] Defender exclusions — {}:", label);
            enum_exclusion_key(hkey, label);
            unsafe { let _ = reg_close_key(hkey); };
            any_found = true;
        }
    }

    if !any_found {
        println!("{}", obf!("[-] No Defender exclusions found (or access denied)."));
    }

    Ok(())
}
